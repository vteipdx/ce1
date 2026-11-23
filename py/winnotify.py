"""
winnotify.py -- WinNotify.sys kernel bridge, pure-Python port of src/PhysicalMemory.pas

What it does (mirrors the Pascal unit 1:1):
  * locate WinNotify.sys / signeddrv.sys
  * register + start it as a kernel service (needs Administrator)
  * open the control device \\\\.\\WinNotify
  * IOCTL 0x22200C  ntoskrnl base disclosure
  * IOCTL 0x222040  arbitrary kernel QWORD read
  * IOCTL 0x222044  arbitrary kernel QWORD write (memmove)
  * IOCTL 0x222050/54  physical R/W with DirBase (CR3 page walk, done by driver)
  * EPROCESS walk -> target CR3
  * ReadProcessMemory / WriteProcessMemory through the target's page tables
    (no OpenProcess handle is required for the kernel path)

Every IOCTL packet is configurable from a JSON sidecar (winnotify.json),
because driver builds differ.  The default binary format is byte-for-byte what
src/PhysicalMemory.pas sends, so if the Pascal bridge works on your driver this
works too.
"""
import ctypes
import json
import os
import struct
import sys
import time

from ctypes import wintypes

IS_WINDOWS = sys.platform.startswith("win")

# ---------------------------------------------------------------------------
# Win32 constants
# ---------------------------------------------------------------------------
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
TH32CS_SNAPPROCESS = 0x00000002

SC_MANAGER_ALL_ACCESS = 0xF003F
SERVICE_START = 0x0010
SERVICE_STOP = 0x0020
SERVICE_QUERY_STATUS = 0x0004
SERVICE_CHANGE_CONFIG = 0x0002
DELETE_ACCESS = 0x00010000
SERVICE_KERNEL_DRIVER = 0x1
SERVICE_DEMAND_START = 0x3
SERVICE_ERROR_NORMAL = 0x1
SERVICE_CONTROL_STOP = 0x1
ERROR_SERVICE_ALREADY_RUNNING = 1056
ERROR_SERVICE_MARKED_FOR_DELETE = 1072
ERROR_SERVICE_EXISTS = 1073

TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002
ERROR_NOT_ALL_ASSIGNED = 1300
ERROR_BAD_LENGTH = 24

DEFAULT_DRIVER_NAME = "WinNotify"
DEFAULT_DEVICE_PATH = r"\\.\WinNotify"


# ---------------------------------------------------------------------------
# Default profile -- identical numbers to src/PhysicalMemory.pas
# ---------------------------------------------------------------------------
DEFAULT_CONFIG = {
    # verified against the public RE of signeddrv.sys / WinNotify.sys:
    # 40-byte fixed structs, METHOD_OUT_DIRECT / METHOD_IN_DIRECT
    "ioctl_info": 0x22200C,        # module base:   [name]            -> +0x10
    "ioctl_read": 0x222040,        # kernel read:   [base][offset]    -> out[0x10..0x30] (5 QWORDs)
    "ioctl_write": 0x222044,       # kernel write:  [src][size][dst]  (METHOD_IN_DIRECT)
    "ioctl_vread": 0x222000,       # virtual read:  [0][va][buf][size][cr3]
    "ioctl_vwrite": 0x222004,      # virtual write: [0][va][buf][size][cr3]
    "device_path": DEFAULT_DEVICE_PATH,
    "service_name": DEFAULT_DRIVER_NAME,
    "driver_search": [
        r"C:\Windows\System32\drivers\WinNotify.sys",
        "exe_dir\\WinNotify.sys",
        "exe_dir\\signeddrv.sys",
        r"C:\Windows\System32\drivers\signeddrv.sys",
    ],
    "info_module_names": ["ntoskrnl.exe", "ntoskrnl"],
    # The driver validates the *exact* input length per IOCTL and fails with
    # ERROR_BAD_LENGTH (24) otherwise -- these are the lengths from the RE.
    "info_in_size": 0x18,          # 24
    "info_out_size": 0x20,         # 32
    "info_result_offset": 0x10,
    "read_in_size": 0x38,          # 56
    "read_out_size": 0x40,         # 64
    "read_bias": 0x10,             # reading T needs base = T - 0x10
    "read_result_offset": 0x20,    # out[2] = *(base+0x10) = *T
    "read_qwords": 5,
    "write_in_size": 0x18,         # 24
    "write_out_size": 0,
    "vioctl_size": 0x28,           # 40, input == output struct
    "vioctl_layout": 0,            # 0 = [flags][va][buf][size][cr3]
    "vioctl_probe_sizes": [0x28, 0x20],
    "info_probe_sizes": [0x18, 0x28],
    "info_probe_out_sizes": [0x20, 0x40],
    "read_probe_sizes": [0x38, 0x40],
    "read_probe_biases": [0x10, 0],
    "write_probe_sizes": [0x18, 0x28],
    "autodetect": True,
    "use_direct_vioctl": True,     # 0x222000/0x222004 page-table R/W path
    "vread_first_field_is_zero": True,
    "phys_page_size": 0x1000,
    "eprocess_links": 0x448,
    "eprocess_pid": 0x440,
    "eprocess_dtb": 0x28,
    "eprocess_probe_shifts": [0x10, 0],   # Win11 24H2+ shifted pid/links by 0x10
    # PsInitialSystemProcess relative to ntoskrnl, tried in order:
    # Win11 24H2/25H2, Win10 22H2, Win11 23H2, Win11 21H2, Win10 21H1
    "ps_initial_system_offsets": [
        0xD8C420, 0xCFC420, 0xD19420, 0xD0A420, 0xCFC3E0,
    ],
    "cr3_mask": 0x000FFFFFFFFFF000,
    "keep_service": True,
}

_INT_KEYS = {
    "ioctl_info", "ioctl_read", "ioctl_write", "ioctl_vread", "ioctl_vwrite",
    "info_in_size", "info_out_size", "info_result_offset",
    "read_in_size", "read_out_size", "read_bias", "read_result_offset",
    "read_qwords", "write_in_size", "write_out_size", "vioctl_size",
    "phys_page_size", "eprocess_links", "eprocess_pid",
    "eprocess_dtb", "cr3_mask",
}
_INT_LIST_KEYS = {"ps_initial_system_offsets"}


def _as_int(value):
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


def normalize_config(raw):
    """Accept "0x448" style strings in the JSON profile."""
    cfg = dict(DEFAULT_CONFIG)
    for key, value in raw.items():
        if key not in cfg:
            continue
        if key in _INT_KEYS:
            cfg[key] = _as_int(value)
        elif key in _INT_LIST_KEYS:
            cfg[key] = [_as_int(v) for v in value]
        elif key == "driver_search":
            cfg[key] = [str(v) for v in value]
        else:
            cfg[key] = value
    return cfg


def load_config(exe_dir=None, explicit=None):
    cfg_raw = {}
    search = []
    if explicit:
        search.append(explicit)
    if exe_dir:
        search.append(os.path.join(exe_dir, "winnotify.json"))
    search.append(os.path.join(os.getcwd(), "winnotify.json"))
    for path in search:
        try:
            if path and os.path.isfile(path):
                with open(path, "r", encoding="utf-8") as fh:
                    cfg_raw = json.load(fh)
                break
        except (OSError, ValueError):
            continue
    cfg = normalize_config(cfg_raw)
    if exe_dir:
        cfg["driver_search"] = [
            p.replace("exe_dir", exe_dir) for p in cfg["driver_search"]
        ]
    return cfg


# ---------------------------------------------------------------------------
# Win32 structures
# ---------------------------------------------------------------------------
class _SERVICE_STATUS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
    ]


class _SERVICE_STATUS_PROCESS(ctypes.Structure):
    _fields_ = _SERVICE_STATUS._fields_ + [
        ("dwProcessId", wintypes.DWORD),
        ("dwServiceFlags", wintypes.DWORD),
    ]


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class _LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]


class _TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", _LUID_AND_ATTRIBUTES * 1),
    ]


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class WinNotifyError(RuntimeError):
    pass


class WinNotifyIoctlError(WinNotifyError):
    """DeviceIoControl failed; keeps the IOCTL code and GetLastError value."""

    def __init__(self, message, ioctl_code=0, winerror=0):
        super().__init__(message)
        self.ioctl_code = ioctl_code
        self.winerror = winerror



# ---------------------------------------------------------------------------
# Win32 API bindings
#
# NOTE: LookupPrivilegeValueW / AdjustTokenPrivileges live in ADVAPI32, not
# kernel32.  Functions are also looked up one by one (via `try_getattr`) and
# bound with $(...) signatures, so a missing entry point can never break the
# import and the 32/64-bit calling convention is always the WinAPI one.
# ---------------------------------------------------------------------------
def _try_getattr(dll, name):
    """Return dll.name or None instead of raising AttributeError."""
    try:
        return getattr(dll, name)
    except AttributeError:
        return None
    except OSError:
        return None


def _signature(name, argtypes, restype):
    """ctypes prototype; silently skipped if the export does not exist."""
    def apply(dll):
        fn = _try_getattr(dll, name)
        if fn is not None:
            fn.argtypes = argtypes
            fn.restype = restype
        return fn
    return apply


SIGNATURES = {
    "kernel32": [
        _signature("CreateFileW", [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ], wintypes.HANDLE),
        _signature("CloseHandle", [wintypes.HANDLE], wintypes.BOOL),
        _signature("DeviceIoControl", [
            wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ], wintypes.BOOL),
        _signature("GetCurrentProcess", [], wintypes.HANDLE),
        _signature("CreateToolhelp32Snapshot", [
            wintypes.DWORD, wintypes.DWORD], wintypes.HANDLE),
        _signature("Process32FirstW", [
            wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)], wintypes.BOOL),
        _signature("Process32NextW", [
            wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)], wintypes.BOOL),
        _signature("GetModuleHandleW", [wintypes.LPCWSTR], wintypes.HMODULE),
    ],
    "advapi32": [
        _signature("LookupPrivilegeValueW", [
            wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)],
            wintypes.BOOL),
        _signature("AdjustTokenPrivileges", [
            wintypes.HANDLE, wintypes.BOOL, ctypes.c_void_p, wintypes.DWORD,
            ctypes.c_void_p, ctypes.c_void_p], wintypes.BOOL),
        _signature("OpenProcessToken", [
            wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)],
            wintypes.BOOL),
        _signature("OpenSCManagerW", [
            wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD],
            wintypes.HANDLE),
        _signature("CreateServiceW", [
            wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
            wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPCWSTR,
            wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD), wintypes.LPCWSTR,
            wintypes.LPCWSTR, wintypes.LPCWSTR], wintypes.HANDLE),
        _signature("OpenServiceW", [
            wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD], wintypes.HANDLE),
        _signature("StartServiceW", [
            wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.LPCWSTR)],
            wintypes.BOOL),
        _signature("ControlService", [
            wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(_SERVICE_STATUS)],
            wintypes.BOOL),
        _signature("QueryServiceStatusEx", [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
        _signature("DeleteService", [wintypes.HANDLE], wintypes.BOOL),
        _signature("CloseServiceHandle", [wintypes.HANDLE], wintypes.BOOL),
    ],
}


def _load_library(name):
    """Load a system DLL, or return None when it cannot be loaded."""
    for loader in (getattr(ctypes, "WinDLL", None), None):
        if loader is None:
            continue
        try:
            return loader(name, use_last_error=True)
        except OSError:
            try:
                return loader(name)
            except OSError:
                continue
    return None


def _bind_apis():
    k32 = _load_library("kernel32")
    adv = _load_library("advapi32")
    for spec in SIGNATURES["kernel32"]:
        if k32 is not None:
            spec(k32)
    for spec in SIGNATURES["advapi32"]:
        if adv is not None:
            spec(adv)
    return k32, adv


class _MissingApi:
    """Placeholder that fails with a readable message instead of AttributeError."""

    def __init__(self, name):
        object.__setattr__(self, "_name", name)

    def __getattr__(self, item):
        # only reached for unknown attributes, so this is never part of
        # normal ctypes binding -- turn it into a friendly message
        raise WinNotifyError(
            f"{self._name} is not available on this system (missing {item})"
        )

    def __str__(self):
        return f"<{self._name} unavailable>"


_k32, _adv = _bind_apis() if IS_WINDOWS else (None, None)
if IS_WINDOWS:
    if _k32 is None or _adv is None:
        # last-resort fallback: try every known export through ctypes.windll
        if _k32 is None:
            _k32 = _MissingApi("kernel32")
        if _adv is None:
            _adv = _MissingApi("advapi32")


def _api(dll, name):
    """Fetch a bound function or raise a clean error."""
    fn = _try_getattr(dll, name)
    if fn is None:
        raise WinNotifyError(f"function {name} not found (unexpected Windows build?)")
    return fn


def _require_windows():
    if not IS_WINDOWS:
        raise WinNotifyError("the WinNotify bridge only runs on Windows")


def _host_dll():
    """GetModuleHandleW(None) == HMODULE of the running process image."""
    fn = _api(_k32, "GetModuleHandleW")
    handle = fn(None)
    if handle is None:
        raise WinNotifyError("GetModuleHandleW failed")
    if not isinstance(handle, int):
        handle = ctypes.cast(handle, ctypes.c_void_p).value
    return int(handle or 0)


def _last_error():
    if IS_WINDOWS:
        return ctypes.get_last_error()
    return 0


def _winerr(prefix):
    err = _last_error()
    try:
        text = ctypes.FormatError(err).strip()
    except Exception:
        text = ""
    return WinNotifyError(f"{prefix} (WinError {err}: {text})")


# ---------------------------------------------------------------------------
# Privileges
# ---------------------------------------------------------------------------
def enable_privilege(name):
    """Enable a token privilege (SeLoadDriverPrivilege) for this process."""
    _require_windows()
    open_process_token = _api(_adv, "OpenProcessToken")
    lookup_privilege = _api(_adv, "LookupPrivilegeValueW")
    adjust_privileges = _api(_adv, "AdjustTokenPrivileges")
    close_handle = _api(_k32, "CloseHandle")

    token = wintypes.HANDLE()
    if not open_process_token(
        _api(_k32, "GetCurrentProcess")(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(token),
    ):
        raise _winerr("OpenProcessToken")
    try:
        luid = LUID()
        if not lookup_privilege(None, name, ctypes.byref(luid)):
            raise _winerr("LookupPrivilegeValue " + name)
        tp = _TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        if not adjust_privileges(token, False, ctypes.byref(tp), 0, None, None):
            raise _winerr("AdjustTokenPrivileges " + name)
        if _last_error() == ERROR_NOT_ALL_ASSIGNED:
            raise WinNotifyError(f"privilege {name} is not held by this token")
    finally:
        close_handle(token)
    return True


# ---------------------------------------------------------------------------
# Driver + device
# ---------------------------------------------------------------------------
class WinNotify:
    def __init__(self, exe_dir=None, config=None, log=print):
        self.exe_dir = exe_dir or os.path.dirname(os.path.abspath(sys.argv[0]))
        self.cfg = config or load_config(self.exe_dir)
        self.log = log
        self.device = None
        self.driver_path = None
        self.service_name = self.cfg["service_name"]
        self.kernel_base = 0
        self._eprocess_cache = {}

    # -- driver service ----------------------------------------------------
    def find_driver(self):
        for path in self.cfg["driver_search"]:
            if path and os.path.isfile(path):
                return path
        return None

    def load_driver(self, driver_path=None):
        _require_windows()
        driver_path = driver_path or self.find_driver()
        if not driver_path:
            raise WinNotifyError(
                "WinNotify.sys not found, looked in: "
                + ", ".join(self.cfg["driver_search"])
            )
        driver_path = os.path.abspath(driver_path)
        if not os.path.isfile(driver_path):
            raise WinNotifyError(f"driver file does not exist: {driver_path}")
        self.driver_path = driver_path

        try:
            enable_privilege("SeLoadDriverPrivilege")
        except WinNotifyError as exc:
            self.log(f"[!] SeLoadDriverPrivilege: {exc}")

        open_scm = _api(_adv, "OpenSCManagerW")
        create_service = _api(_adv, "CreateServiceW")
        open_service = _api(_adv, "OpenServiceW")
        start_service = _api(_adv, "StartServiceW")
        close_scm = _api(_adv, "CloseServiceHandle")

        scm = open_scm(None, None, SC_MANAGER_ALL_ACCESS)
        if not scm:
            raise _winerr("OpenSCManager (run as Administrator)")
        try:
            svc = create_service(
                scm, self.service_name, self.service_name,
                SERVICE_START | SERVICE_STOP | SERVICE_CHANGE_CONFIG,
                SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL, driver_path,
                None, None, None, None, None,
            )
            if not svc:
                err = _last_error()
                if err in (ERROR_SERVICE_EXISTS, ERROR_SERVICE_MARKED_FOR_DELETE):
                    svc = open_service(
                        scm, self.service_name,
                        SERVICE_START | SERVICE_STOP | SERVICE_CHANGE_CONFIG,
                    )
                if not svc:
                    raise _winerr(f"CreateService({self.service_name})")
            try:
                if not start_service(svc, 0, None):
                    err = _last_error()
                    if err != ERROR_SERVICE_ALREADY_RUNNING:
                        raise _winerr(f"StartService({self.service_name})")
            finally:
                close_scm(svc)
        finally:
            close_scm(scm)
        self.log(f"[+] driver loaded: {driver_path} as '{self.service_name}'")

    def unload_driver(self):
        _require_windows()
        scm = _api(_adv, "OpenSCManagerW")(None, None, SC_MANAGER_ALL_ACCESS)
        if not scm:
            return False
        close_scm = _api(_adv, "CloseServiceHandle")
        try:
            svc = _api(_adv, "OpenServiceW")(
                scm, self.service_name,
                SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE_ACCESS,
            )
            if not svc:
                return False
            try:
                status = _SERVICE_STATUS()
                _api(_adv, "ControlService")(svc, SERVICE_CONTROL_STOP,
                                             ctypes.byref(status))
                _api(_adv, "DeleteService")(svc)
            finally:
                close_scm(svc)
            self.log(f"[+] driver service '{self.service_name}' removed")
            return True
        finally:
            close_scm(scm)

    # -- device ------------------------------------------------------------
    def open_device(self):
        _require_windows()
        handle = _api(_k32, "CreateFileW")(
            self.cfg["device_path"], GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None,
        )
        if not handle or handle == INVALID_HANDLE_VALUE:
            raise _winerr(f"CreateFile({self.cfg['device_path']})")
        self.device = handle
        self.log(f"[+] device opened: {self.cfg['device_path']}")

    # -- ioctl plumbing ----------------------------------------------------
    def ioctl(self, code, in_buf=b"", out_size=None, in_size=None):
        """Send one IOCTL and return the raw buffer the driver answered in.

        The driver checks the input length against a fixed value per IOCTL and
        fails with ERROR_BAD_LENGTH (24) on a mismatch, so `in_size`/`out_size`
        must be exactly what that request expects.  Everything is sent through
        one buffer: the driver writes its answer back into it.
        """
        _require_windows()
        if not self.device:
            raise WinNotifyError("device is not open")
        payload = bytes(in_buf)
        in_size = len(payload) if in_size is None else in_size
        if out_size is None:
            out_size = in_size
        if len(payload) < in_size:
            payload = payload.ljust(in_size, b"\x00")
        total = max(in_size, out_size)
        if len(payload) < total:
            payload = payload.ljust(total, b"\x00")
        buf = ctypes.create_string_buffer(payload, total)
        returned = wintypes.DWORD(0)
        ok = _api(_k32, "DeviceIoControl")(
            self.device, code, buf, in_size, buf, out_size,
            ctypes.byref(returned), None,
        )
        if not ok:
            err = _last_error()
            exc = WinNotifyIoctlError(
                f"DeviceIoControl(0x{code:X}) (WinError {err})", code, err)
            if err == ERROR_BAD_LENGTH:
                exc = WinNotifyIoctlError(
                    f"DeviceIoControl(0x{code:X}) WinError 24 "
                    f"(the driver rejected the {in_size}-byte input struct)",
                    code, err)
            raise exc
        data = buf.raw
        if len(data) < out_size:
            data = data.ljust(out_size, b"\x00")
        return data

    # -- kernel base -------------------------------------------------------
    def get_kernel_base(self, autodetect=True):
        in_size = self.cfg["info_in_size"]
        out_size = self.cfg["info_out_size"]
        off = self.cfg["info_result_offset"]
        last = None
        for name in self.cfg["info_module_names"]:
            in_buf = (name.encode("ascii") + b"\x00")[:in_size].ljust(in_size, b"\x00")
            try:
                out = self.ioctl(self.cfg["ioctl_info"], in_buf,
                                 out_size=out_size, in_size=in_size)
            except WinNotifyIoctlError as exc:
                last = exc
                continue
            if len(out) >= off + 8:
                base = int.from_bytes(out[off:off + 8], "little")
                if base:
                    self.kernel_base = base
                    return base
        if last and last.winerror == ERROR_BAD_LENGTH and autodetect:
            return self._probe_kernel_base()
        if last:
            raise WinNotifyError(f"{last}  [module-base IOCTL layout mismatch?]")
        raise WinNotifyError("driver returned no kernel base")

    def _probe_kernel_base(self):
        """Find the input length this driver build accepts for 0x22200C.

        Different WinNotify builds use 0x18 (documented) or 0x28 (what the
        Pascal bridge assumed) byte input structs; both write the base to
        +0x10 of the reply.  Probing keeps the tool working on either.
        """
        name = self.cfg["info_module_names"][0].encode("ascii") + b"\x00"
        for in_size in self.cfg.get("info_probe_sizes", [0x18, 0x28]):
            for out_size in self.cfg.get("info_probe_out_sizes", [0x20, 0x40]):
                packet = name.ljust(in_size, b"\x00")[:in_size]
                try:
                    out = self.ioctl(self.cfg["ioctl_info"], packet,
                                     out_size=out_size, in_size=in_size)
                except WinNotifyError:
                    continue
                base = int.from_bytes(out[0x10:0x18], "little")
                if base and base >> 48 == 0xFFFF:
                    self.cfg["info_in_size"] = in_size
                    self.cfg["info_out_size"] = out_size
                    self.kernel_base = base
                    self.log(f"[i] module-base IOCTL auto-detected: "
                             f"in=0x{in_size:X} out=0x{out_size:X}")
                    return base
        raise WinNotifyError(
            "0x22200C rejects every known input size -- this driver build has a "
            "different module-base IOCTL; set ioctl_info/info_in_size in "
            "winnotify.json")

    # -- arbitrary kernel read / write -------------------------------------
    def _read_packet(self, addr, in_size, bias):
        base = (addr - bias) & 0xFFFFFFFFFFFFFFFF
        packet = base.to_bytes(8, "little") + (0).to_bytes(8, "little")
        return packet.ljust(in_size, b"\x00")[:in_size]

    def read_kernel_qwords(self, addr):
        """One READ IOCTL returns 5 consecutive QWORDs at addr."""
        in_size = self.cfg["read_in_size"]
        out_size = self.cfg["read_out_size"]
        packet = self._read_packet(addr, in_size, self.cfg["read_bias"])
        try:
            out = self.ioctl(self.cfg["ioctl_read"], packet,
                             out_size=out_size, in_size=in_size)
        except WinNotifyIoctlError as exc:
            if exc.winerror != ERROR_BAD_LENGTH or not self.cfg.get("autodetect", True):
                raise
            return [self.read_qword(addr)]
        start = self.cfg["read_bias"]
        vals = []
        for i in range(self.cfg["read_qwords"]):
            off = start + i * 8
            if len(out) < off + 8:
                break
            vals.append(int.from_bytes(out[off:off + 8], "little"))
        return vals or [0]

    def read_qword(self, addr, autodetect=True):
        """Read one kernel QWORD.

        Reply layout: out[0x10] = *(base+0), ..., out[0x20] = *(base+0x10).
        The driver only answers when *(base+0x10) != 0, so the request is
        biased by 0x10 and the wanted value lands on the checked slot.
        """
        in_size = self.cfg["read_in_size"]
        out_size = self.cfg["read_out_size"]
        bias = self.cfg["read_bias"]
        packet = self._read_packet(addr, in_size, bias)
        try:
            out = self.ioctl(self.cfg["ioctl_read"], packet,
                             out_size=out_size, in_size=in_size)
        except WinNotifyIoctlError as exc:
            if exc.winerror == ERROR_BAD_LENGTH and autodetect:
                return self._probe_read_qword(addr)
            raise
        off = self.cfg["read_result_offset"]
        if len(out) < off + 8:
            return 0
        return int.from_bytes(out[off:off + 8], "little")

    def _probe_read_qword(self, addr):
        """Try the input-length / bias combinations different builds accept."""
        for in_size in self.cfg.get("read_probe_sizes", [0x38, 0x40]):
            for bias in self.cfg.get("read_probe_biases", [0x10, 0]):
                out_size = max(in_size + 8, 0x40)
                packet = self._read_packet(addr, in_size, bias)
                try:
                    out = self.ioctl(self.cfg["ioctl_read"], packet,
                                     out_size=out_size, in_size=in_size)
                except WinNotifyError:
                    continue
                off = bias + 0x10          # slot the driver checked
                if len(out) < off + 8:
                    continue
                self.cfg["read_in_size"] = in_size
                self.cfg["read_out_size"] = out_size
                self.cfg["read_bias"] = bias
                self.cfg["read_result_offset"] = off
                self.log(f"[i] kernel-read IOCTL auto-detected: "
                         f"in=0x{in_size:X} bias=0x{bias:X}")
                return int.from_bytes(out[off:off + 8], "little")
        raise WinNotifyError(
            "0x222040 rejects every known input size -- this driver build has a "
            "different kernel-read IOCTL; set ioctl_read/read_in_size in "
            "winnotify.json")

    def write_qword(self, addr, value):
        # METHOD_IN_DIRECT: struct = {src_ptr, size, dst}; driver memmoves
        # `size` bytes from src into the kernel address dst.
        src = ctypes.c_uint64(value & 0xFFFFFFFFFFFFFFFF)
        body = (
            ctypes.addressof(src).to_bytes(8, "little")
            + (8).to_bytes(8, "little")
            + (addr & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        )
        last = None
        for in_size in self.cfg.get("write_probe_sizes",
                                    [self.cfg["write_in_size"], 0x28]):
            packet = body.ljust(in_size, b"\x00")[:in_size]
            try:
                self.ioctl(self.cfg["ioctl_write"], packet,
                           out_size=self.cfg["write_out_size"], in_size=in_size)
            except WinNotifyIoctlError as exc:
                last = exc
                if exc.winerror == ERROR_BAD_LENGTH:
                    continue
                raise
            self.cfg["write_in_size"] = in_size
            return
        if last:
            raise last

    # -- virtual R/W through a supplied DirBase (CR3) ----------------------
    def _vioclt_packet(self, cr3, addr, buf_ptr, size, layout=None, st=None):
        """layout 0 (documented): [flags][va][buf][size][cr3]
        layout 1 (legacy/Pascal): [cr3][va][size][buf]"""
        st = st or self.cfg["vioctl_size"]
        if layout is None:
            layout = self.cfg.get("vioctl_layout", 0)
        if layout == 0:
            first = 0 if self.cfg.get("vread_first_field_is_zero", True) else size
            packet = (
                (first & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
                + (addr & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
                + (buf_ptr & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
                + (size & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
                + (cr3 & self.cfg["cr3_mask"]).to_bytes(8, "little")
            )
        else:
            packet = (
                (cr3 & self.cfg["cr3_mask"]).to_bytes(8, "little")
                + (addr & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
                + (size & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
                + (buf_ptr & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
            )
        return packet.ljust(st, b"\x00")[:st]

    def _vread(self, cr3, addr, buf_ptr, size):
        st = self.cfg["vioctl_size"]
        packet = self._vioclt_packet(cr3, addr, buf_ptr, size, st=st)
        try:
            self.ioctl(self.cfg["ioctl_vread"], packet, out_size=st, in_size=st)
        except WinNotifyIoctlError as exc:
            if exc.winerror == ERROR_BAD_LENGTH and self.cfg.get("autodetect", True):
                self._probe_vioctl(cr3, addr, buf_ptr, size, write=False)
                return
            raise

    def _vwrite(self, cr3, addr, buf_ptr, size):
        st = self.cfg["vioctl_size"]
        packet = self._vioclt_packet(cr3, addr, buf_ptr, size, st=st)
        try:
            self.ioctl(self.cfg["ioctl_vwrite"], packet, out_size=st, in_size=st)
        except WinNotifyIoctlError as exc:
            if exc.winerror == ERROR_BAD_LENGTH and self.cfg.get("autodetect", True):
                self._probe_vioctl(cr3, addr, buf_ptr, size, write=True)
                return
            raise

    def _probe_vioctl(self, cr3, addr, buf_ptr, size, write):
        """Find this build's virtual R/W struct: 0x28 [flags][va][buf][size][cr3]
        (documented) or 0x20 [cr3][va][size][buf] (legacy bridge)."""
        code = self.cfg["ioctl_vwrite"] if write else self.cfg["ioctl_vread"]
        for st in self.cfg.get("vioctl_probe_sizes", [0x28, 0x20]):
            for layout in (0, 1):
                packet = self._vioclt_packet(cr3, addr, buf_ptr, size,
                                             layout=layout, st=st)
                try:
                    self.ioctl(code, packet, out_size=st, in_size=st)
                except WinNotifyError:
                    continue
                self.cfg["vioctl_size"] = st
                self.cfg["vioctl_layout"] = layout
                self.log(f"[i] virtual-RW IOCTL auto-detected: size=0x{st:X} "
                         f"layout={layout}")
                return True
        raise WinNotifyError(
            f"0x{code:X} rejects every known input size -- set "
            "ioctl_vread/ioctl_vwrite/vioctl_size in winnotify.json")

    # -- EPROCESS navigation ----------------------------------------------
    def _eprocess_layouts(self):
        """(pid, links, dtb) triples to try: the known one plus shifted ones."""
        base = (self.cfg["eprocess_pid"], self.cfg["eprocess_links"],
                self.cfg["eprocess_dtb"])
        found = getattr(self, "_layout", None)
        if found is not None:
            return [found]
        layouts = [base]
        # DirectoryTableBase sits inside KPROCESS, i.e. at the very start of
        # EPROCESS, and did NOT move on 24H2; only pid/links/token shifted.
        for shift in self.cfg.get("eprocess_probe_shifts", [0x10]):
            layouts.append((base[0] + shift, base[1] + shift, base[2]))
        return layouts

    def find_system_eprocess(self):
        if not self.kernel_base:
            self.get_kernel_base()
        for pid_off, links_off, dtb_off in self._eprocess_layouts():
            for off in self.cfg["ps_initial_system_offsets"]:
                ptr = self.read_qword(self.kernel_base + off)
                if not ptr or (ptr >> 48) != 0xFFFF:
                    continue
                if self.read_qword(ptr + pid_off) == 4:
                    if (pid_off, links_off, dtb_off) != (
                            self.cfg["eprocess_pid"], self.cfg["eprocess_links"],
                            self.cfg["eprocess_dtb"]) and not getattr(
                                self, "_layout_logged", False):
                        self.log(f"[i] EPROCESS layout auto-detected: pid=0x{pid_off:X} "
                                 f"links=0x{links_off:X} dtb=0x{dtb_off:X}")
                        self._layout_logged = True
                    self._layout = (pid_off, links_off, dtb_off)
                    self._system_eprocess = ptr
                    return ptr
        return 0

    def find_process_eprocess(self, pid, max_iter=4000):
        pid = int(pid)
        if pid in self._eprocess_cache:
            return self._eprocess_cache[pid]
        sysproc = self.find_system_eprocess()
        if not sysproc:
            return 0
        _, links, _ = getattr(self, "_layout", (
            self.cfg["eprocess_pid"], self.cfg["eprocess_links"],
            self.cfg["eprocess_dtb"]))
        pid_off = self._layout[0]
        current = sysproc
        for _ in range(max_iter):
            flink = self.read_qword(current + links)
            if not flink:
                return 0
            current = flink - links
            if self.read_qword(current + pid_off) == pid:
                self._eprocess_cache[pid] = current
                return current
            if current == sysproc:
                break
        return 0

    def get_process_cr3(self, pid):
        eproc = self.find_process_eprocess(pid)
        if not eproc:
            return 0
        dtb_off = getattr(self, "_layout", (
            self.cfg["eprocess_pid"], self.cfg["eprocess_links"],
            self.cfg["eprocess_dtb"]))[2]
        dtb = self.read_qword(eproc + dtb_off)
        return dtb & self.cfg["cr3_mask"]

    # -- virtual memory R/W through the target's page tables ---------------
    #
    # Primary path: kernel IOCTL 0x222000 / 0x222004, which take the target's
    # DirBase (CR3) directly and do the page-table walk inside the driver.
    # Fallback (profile switch `use_direct_vioctl: false`): the same
    # read-page / patch-4-bytes / write-page loop done with 0x222040+0x222044.
    def read_memory(self, pid, addr, size):
        if size < 0:
            raise ValueError("negative size")
        if size == 0:
            return b""
        cr3 = self.get_process_cr3(pid)
        if not cr3:
            raise WinNotifyError(f"pid {pid}: CR3 not found (unknown process?)")
        addr &= 0xFFFFFFFFFFFFFFFF
        if not self.cfg.get("use_direct_vioctl", True):
            return self._read_memory_via_kernel(cr3, addr, size)

        buf = ctypes.create_string_buffer(size)
        ptr = ctypes.addressof(buf)
        page = self.cfg["phys_page_size"]
        done = 0
        while done < size:
            cur = addr + done
            off = cur & (page - 1)
            take = min(page - off, size - done)
            self._vread(cr3, cur, ptr + done, take)
            done += take
        return buf.raw

    def _read_memory_via_kernel(self, cr3, addr, size):
        page = self.cfg["phys_page_size"]
        out = bytearray()
        done = 0
        while done < size:
            cur = addr + done
            off = cur & (page - 1)
            take = min(page - off, size - done)
            chunk = self._kernel_read_region(cur & ~(page - 1), page)
            if chunk is None:
                raise WinNotifyError(f"read 0x{cur:X}: kernel read failed")
            out += chunk[off:off + take]
            done += take
        return bytes(out)

    def _kernel_read_region(self, addr, size):
        """Up to one page, in 5-QWORD (0x28 byte) strides, via 0x222040."""
        page = self.cfg["phys_page_size"]
        stride = self.cfg["read_qwords"] * 8
        out = bytearray()
        cur = addr
        end = addr + min(size, page)
        while cur < end:
            take = min(stride, end - cur)
            vals = self.read_kernel_qwords(cur, self.cfg["read_qwords"])
            raw = b"".join(v.to_bytes(8, "little") for v in vals)
            out += raw[:take]
            cur += take
        return bytes(out)

    def write_memory(self, pid, addr, data):
        data = bytes(data)
        if not data:
            return
        addr &= 0xFFFFFFFFFFFFFFFF
        cr3 = self.get_process_cr3(pid)
        if not cr3:
            raise WinNotifyError(f"pid {pid}: CR3 not found (unknown process?)")
        if not self.cfg.get("use_direct_vioctl", True):
            self._write_memory_via_kernel(cr3, addr, data)
            return

        page = self.cfg["phys_page_size"]
        buf = ctypes.create_string_buffer(data, len(data))
        ptr = ctypes.addressof(buf)
        done = 0
        while done < len(data):
            cur = addr + done
            off = cur & (page - 1)
            take = min(page - off, len(data) - done)
            self._vwrite(cr3, cur, ptr + done, take)
            done += take

    def _write_memory_via_kernel(self, cr3, addr, data):
        page = self.cfg["phys_page_size"]
        done = 0
        while done < len(data):
            cur = addr + done
            off = cur & (page - 1)
            take = min(page - off, len(data) - done)
            va_page = cur & ~(page - 1)
            if off == 0 and take == page:
                chunk = data[done:done + take]
            else:
                # read-modify-write so the rest of the page stays intact
                old = self._kernel_read_region(va_page, page)
                if old is None:
                    raise WinNotifyError(f"write 0x{cur:X}: page read failed")
                chunk = old[:off] + data[done:done + take] + old[off + take:]
            for i in range(0, len(chunk), 8):
                word = chunk[i:i + 8].ljust(8, b"\x00")
                self.write_qword(va_page + i, int.from_bytes(word, "little"))
            done += take

    # -- convenience -------------------------------------------------------
    def read_dword(self, pid, addr):
        return struct.unpack("<I", self.read_memory(pid, addr, 4))[0]

    def read_int32(self, pid, addr):
        return struct.unpack("<i", self.read_memory(pid, addr, 4))[0]

    def write_int32(self, pid, addr, value):
        self.write_memory(pid, addr, struct.pack("<i", int(value)))

    def write_float(self, pid, addr, value):
        self.write_memory(pid, addr, struct.pack("<f", float(value)))

    # -- lifecycle ---------------------------------------------------------
    def start(self, driver_path=None):
        _require_windows()
        if self.device:
            return self
        # 1) driver may already be loaded from an earlier run
        try:
            self.open_device()
        except WinNotifyError:
            self.load_driver(driver_path)
            last = None
            for _ in range(20):
                try:
                    self.open_device()
                    last = None
                    break
                except WinNotifyError as exc:
                    last = exc
                    time.sleep(0.1)
            if last:
                raise last
        self.get_kernel_base()
        self.log(f"[+] ntoskrnl base: 0x{self.kernel_base:X}")
        return self

    def stop(self, unload=None):
        if self.device:
            _api(_k32, "CloseHandle")(self.device)
            self.device = None
        if unload is None:
            unload = not self.cfg.get("keep_service", True)
        if unload:
            try:
                self.unload_driver()
            except WinNotifyError:
                pass


# ---------------------------------------------------------------------------
# Process lookup
# ---------------------------------------------------------------------------
def find_pids(image_name):
    _require_windows()
    create_snapshot = _api(_k32, "CreateToolhelp32Snapshot")
    process_first = _api(_k32, "Process32FirstW")
    process_next = _api(_k32, "Process32NextW")
    close_handle = _api(_k32, "CloseHandle")

    snap = create_snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == INVALID_HANDLE_VALUE:
        raise _winerr("CreateToolhelp32Snapshot")
    try:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        target = image_name.lower()
        pids = []
        ok = process_first(snap, ctypes.byref(entry))
        while ok:
            if entry.szExeFile.lower() == target:
                pids.append(int(entry.th32ProcessID))
            ok = process_next(snap, ctypes.byref(entry))
        return pids
    finally:
        close_handle(snap)


def resolve_pid(value):
    """Accept a decimal/hex PID or an image name such as PlantsVsZombies.exe."""
    text = str(value).strip()
    try:
        return int(text, 0)
    except ValueError:
        pass
    pids = find_pids(text if text.lower().endswith(".exe") else text + ".exe")
    if not pids:
        raise WinNotifyError(f"process '{text}' is not running")
    return pids[-1]
