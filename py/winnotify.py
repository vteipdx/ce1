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
    # +0x00 of the INFO request must be a *user-mode pointer* to the module
    # name.  Setting this to false sends the name bytes inline, which makes
    # the driver dereference an ASCII constant -> instant bugcheck.
    "info_name_is_pointer": True,
    "ensure_debug_privilege": True,    # 0x22200C needs it, else it answers 0
    "fallback_kernel_base": True,      # NtQuerySystemInformation if the driver says 0
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
    "autodetect": True,                # shape detection of the ioctl structs
    "vet_ioctl_packets": True,         # refuse non-user/non-kernel pointers
    "allow_unknown_ioctl": True,       # guessed IOCTL codes -> e.g. WinError 1
                                       # (raising this to False is dangerous)
    "use_direct_vioctl": True,         # safe path; fallback is opt-in only
    "vioctl_chunk": 0x1000,            # per-IOCTL bytes; smaller = gentler
    "max_process_iter": 2000,     # 0x222000/0x222004 page-table R/W path
    "vread_first_field_is_zero": True,
    "phys_page_size": 0x1000,
    "eprocess_links": 0x448,
    "eprocess_pid": 0x440,
    "eprocess_dtb": 0x28,
    "probe_eprocess_shifts": False,      # opt-in: try pid/links +0x10 (24H2)
    "eprocess_probe_shifts": [0x10],     # only used when the above is true
    # PsInitialSystemProcess relative to ntoskrnl.  Only the FIRST value is
    # used unless "probe_ps_offsets": true -- a wrong offset is harmless in
    # itself (it points into ntoskrnl .data) but every extra dereference is a
    # risk we do not take by default.
    # order: Win10 20H1..22H2 (19041-19045, incl. 21H2 19044), Win11 21H2,
    #        Win11 22H2/23H2, Win11 24H2/25H2
    "ps_initial_system_offsets": [
        0xCFC420, 0xD0A420, 0xD19420, 0xD8C420, 0xCFC3E0,
    ],
    "probe_ps_offsets": False,           # opt-in: try the other candidates
    "preferred_ps_offset": None,         # your build's offset, tried first
    "cr3_mask": 0x000FFFFFFFFFF000,
    "keep_service": True,
}

_INT_KEYS = {
    "ioctl_info", "ioctl_read", "ioctl_write", "ioctl_vread", "ioctl_vwrite",
    "info_in_size", "info_out_size", "info_result_offset",
    "read_in_size", "read_out_size", "read_bias", "read_result_offset",
    "read_qwords", "write_in_size", "write_out_size", "vioctl_size",
    "phys_page_size", "eprocess_links", "eprocess_pid",
    "eprocess_dtb", "cr3_mask", "preferred_ps_offset", "vioctl_chunk",
    "max_process_iter",
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
        _signature("NtCurrentTeb", [], ctypes.c_void_p),
        _signature("VirtualAlloc", [
            ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD],
            ctypes.c_void_p),
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
        _signature("GetTokenInformation", [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
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
def _open_own_token():
    token = wintypes.HANDLE()
    if not _api(_adv, "OpenProcessToken")(
        _api(_k32, "GetCurrentProcess")(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(token),
    ):
        raise _winerr("OpenProcessToken")
    return token


def enable_privilege(name):
    """Enable a token privilege (e.g. SeDebugPrivilege / SeLoadDriverPrivilege).

    Important: administrators hold most privileges *disabled* until something
    enables them.  ZwQuerySystemInformation(SystemModuleInformation) -- which
    the driver uses to resolve module bases -- additionally requires
    SeDebugPrivilege to be ENABLED in the calling token, otherwise it returns
    an empty module list and 0x22200C answers 0.
    """
    _require_windows()
    lookup_privilege = _api(_adv, "LookupPrivilegeValueW")
    adjust_privileges = _api(_adv, "AdjustTokenPrivileges")
    close_handle = _api(_k32, "CloseHandle")

    token = _open_own_token()
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


def token_privileges():
    """Map of privilege name -> enabled? for the current process (diagnostics)."""
    _require_windows()
    GetTokenInformation = _api(_adv, "GetTokenInformation")
    close_handle = _api(_k32, "CloseHandle")
    TOKEN_PRIVILEGES_CLASS = 3
    token = _open_own_token()
    size = wintypes.DWORD(0)
    GetTokenInformation(token, TOKEN_PRIVILEGES_CLASS, None, 0,
                        ctypes.byref(size))
    buf = ctypes.create_string_buffer(size.value or 1)
    result = {}
    try:
        if not GetTokenInformation(token, TOKEN_PRIVILEGES_CLASS, buf,
                                   size.value, ctypes.byref(size)):
            return result
        count = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD))[0]
        arr = ctypes.cast(ctypes.byref(buf, 8),
                          ctypes.POINTER(_LUID_AND_ATTRIBUTES * count)).contents
        for entry in arr:
            result[int(entry.Luid.LowPart)] = bool(
                entry.Attributes & SE_PRIVILEGE_ENABLED)
    finally:
        close_handle(token)
    return result


def privilege_state(name):
    """(present, enabled) for one privilege name."""
    _require_windows()
    luid = LUID()
    if not _api(_adv, "LookupPrivilegeValueW")(None, name, ctypes.byref(luid)):
        return False, False
    state = token_privileges()
    enabled = state.get(int(luid.LowPart), False)
    return int(luid.LowPart) in state, enabled


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
                else:
                    self._started_service = True
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
        self._vet_ioctl_packet(code, payload)
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

    def _vet_ioctl_packet(self, code, payload):
        """Last line of defence before the kernel sees anything.

        The driver trusts every pointer in the request.  A pointer that is not
        in our own process (and not a canonical kernel address where the IOCTL
        expects one) is therefore refused here instead of bugchecking.
        """
        if not self.cfg.get("vet_ioctl_packets", True):
            return
        if code == self.cfg["ioctl_info"]:
            ptr = int.from_bytes(payload[:8].ljust(8, b"\x00"), "little")
            if not self._is_user_ptr(ptr):
                raise WinNotifyError(
                    f"0x{code:X}: +0x00 must be a pointer to the module-name "
                    f"string in our process, got 0x{ptr:X} -- refusing "
                    "(the driver would dereference it)")
        elif code in (self.cfg["ioctl_vread"], self.cfg["ioctl_vwrite"]):
            layout = self.cfg.get("vioctl_layout", 0)
            field = lambda off: int.from_bytes(
                payload[off:off + 8].ljust(8, b"\x00"), "little")
            if layout == 0:            # [flags][va][buf][size][cr3]
                va, buf_ptr, cr3 = field(8), field(0x10), field(0x20)
            else:                      # [cr3][va][size][buf]
                cr3, va, buf_ptr = field(0), field(8), field(0x18)
            if not cr3 and len(payload) == 0x20:
                # legacy struct just sent with the documented layout: the CR3
                # lives at +0x18 there.  Accept either shape for the check --
                # the actual layout is re-detected from the driver's reply.
                alt = field(0x18)
                if 0x1000 <= (alt & 0x000FFFFFFFFFF000) <= 0x000FFFFFFFFFF000:
                    cr3 = alt
            if not self._is_user_ptr(buf_ptr):
                raise WinNotifyError(
                    f"0x{code:X}: data buffer 0x{buf_ptr:X} is not a valid "
                    "user pointer -- refusing")
            if not self._is_user_ptr(va):
                raise WinNotifyError(
                    f"0x{code:X}: 0x{va:X} is not a process virtual address -- "
                    "refusing (a kernel VA here would poison the target CR3)")
            if not (0x1000 <= (cr3 & 0x000FFFFFFFFFF000) <= 0x000FFFFFFFFFF000):
                raise WinNotifyError(
                    f"0x{code:X}: CR3 0x{cr3:X} does not look like a page table")
        elif code == self.cfg["ioctl_write"]:
            src = int.from_bytes(payload[:8].ljust(8, b"\x00"), "little")
            dst = int.from_bytes(payload[0x10:0x18].ljust(8, b"\x00"), "little")
            if not self._is_user_ptr(src):
                raise WinNotifyError(
                    f"0x{code:X}: source 0x{src:X} is not a user pointer -- refusing")
            if not self._is_kernel_ptr(dst):
                raise WinNotifyError(
                    f"0x{code:X}: destination 0x{dst:X} is not a kernel address -- "
                    "refusing")
        elif code == self.cfg["ioctl_read"]:
            base = int.from_bytes(payload[:8].ljust(8, b"\x00"), "little")
            start = (base + self.cfg["read_bias"]) & 0xFFFFFFFFFFFFFFFF
            if not self._is_kernel_ptr(start):
                raise WinNotifyError(
                    f"0x{code:X}: 0x{start:X} is not a kernel address -- refusing")

    # -- kernel base -------------------------------------------------------
    def get_kernel_base(self, autodetect=True):
        """0x22200C: hand the driver a *valid user pointer* to the module name.

        The driver reads a QWORD at +0x00 and uses it as a pointer to the name
        string (it never copies the bytes into the kernel).  Writing the ASCII
        name at +0x00 makes the driver dereference ~0x6C726B736F74746E, i.e. a
        guaranteed bugcheck -- that was the selftest BSOD.  +0x00 is now always
        the address of a string buffer we own.
        """
        in_size = self.cfg["info_in_size"]
        out_size = self.cfg["info_out_size"]
        off = self.cfg["info_result_offset"]
        pointer_mode = self.cfg.get("info_name_is_pointer", True)
        if self.cfg.get("ensure_debug_privilege", True):
            self._ensure_debug_privilege()
        last = None
        for name in self.cfg["info_module_names"]:
            try:
                if pointer_mode:
                    out = self._info_pointer_call(name, in_size, out_size)
                else:
                    packet = (name.encode("ascii") + b"\x00")[:in_size].ljust(
                        in_size, b"\x00")
                    out = self.ioctl(self.cfg["ioctl_info"], packet,
                                     out_size=out_size, in_size=in_size)
            except WinNotifyIoctlError as exc:
                last = exc
                if exc.winerror == ERROR_BAD_LENGTH and pointer_mode:
                    # same semantics, other struct size: retry with a pointer
                    for size in self.cfg.get("info_probe_sizes", [0x18, 0x28]):
                        try:
                            out = self._info_pointer_call(
                                name, size, max(out_size, size))
                        except WinNotifyError:
                            continue
                        cand = int.from_bytes(out[off:off + 8], "little")
                        if cand and self._looks_like_kernel_base(cand):
                            self.cfg["info_in_size"] = size
                            self.cfg["info_out_size"] = max(out_size, size)
                            self.kernel_base = cand
                            self.log(f"[i] module-base IOCTL auto-detected: "
                                     f"pointer, in=0x{size:X}")
                            return cand
                continue
            except WinNotifyError as exc:
                last = exc
                continue
            if len(out) < off + 8:
                last = WinNotifyError("module-base reply was too short")
                continue
            base = int.from_bytes(out[off:off + 8], "little")
            if base and self._looks_like_kernel_base(base):
                self.kernel_base = base
                return base
            if base == 0:
                last = WinNotifyError(
                    "0x22200C answered 0: the driver's module list was empty. "
                    "That happens when SeDebugPrivilege is not enabled in this "
                    "token (run as Administrator) or the driver's internal "
                    "module snapshot failed")
            else:
                last = WinNotifyError(
                    f"module-base reply held 0x{base:X} (not a plausible "
                    "kernel base)")
        if self.cfg.get("fallback_kernel_base", True):
            try:
                base = kernel_base_from_system_info(self.cfg["info_module_names"][0])
                if self._looks_like_kernel_base(base):
                    self.kernel_base = base
                    self.kernel_base_source = "NtQuerySystemInformation"
                    self.log(f"[i] 0x22200C gave nothing ({last}); using "
                             f"NtQuerySystemInformation instead: 0x{base:X}")
                    return base
            except WinNotifyError as exc:
                self.log(f"[!] user-mode module lookup failed too: {exc}")
        if last:
            raise WinNotifyError(f"{last}  [module-base IOCTL layout mismatch?]")
        raise WinNotifyError("driver returned no kernel base")

    def _ensure_debug_privilege(self):
        """The INFO IOCTL goes through ZwQuerySystemInformation(0xb) which
        needs SeDebugPrivilege enabled -- otherwise the driver sees an empty
        module list and returns 0."""
        try:
            present, enabled = privilege_state("SeDebugPrivilege")
        except WinNotifyError:
            return False
        if enabled:
            return True
        if not present:
            self.log("[!] SeDebugPrivilege is not in this token -- run elevated")
            return False
        try:
            enable_privilege("SeDebugPrivilege")
            self.log("[+] SeDebugPrivilege enabled")
            return True
        except WinNotifyError as exc:
            self.log(f"[!] could not enable SeDebugPrivilege: {exc}")
            return False

    def _looks_like_kernel_base(self, value):
        """ntoskrnl is 2 MB aligned and lives in the high half."""
        return (value >> 48) == 0xFFFF and (value & 0x1FFFFF) == 0

    def _info_pointer_call(self, name, in_size, out_size):
        """Send 0x22200C with a pointer to a NUL-terminated name in our memory."""
        buf = ctypes.create_string_buffer(name.encode("ascii"), len(name) + 1)
        packet = (ctypes.addressof(buf).to_bytes(8, "little")
                  + b"\x00" * (in_size - 8))
        return self.ioctl(self.cfg["ioctl_info"], packet[:in_size],
                          out_size=out_size, in_size=in_size)

    # -- arbitrary kernel read / write -------------------------------------
    #
    # Every address below is dereferenced by the driver, so the gate refuses
    # anything that is not a canonical kernel address.  `allow_unknown_ioctl`
    # governs IOCTL *codes* only (a wrong code returns an error, it does not
    # touch memory): keep it True for the shape detection, set it False if you
    # prefer a pure-single-shot run.
    def _gate_kernel_addr(self, addr, what):
        """Nothing but a canonical kernel address may reach 0x222040/0x222044.

        This is unconditional: the driver dereferences the value as-is, so a
        user-mode or non-canonical address here is a one-way ticket to a
        bugcheck.  (`allow_unknown_ioctl` only governs IOCTL *codes*.)
        """
        addr &= 0xFFFFFFFFFFFFFFFF
        if not self._is_kernel_ptr(addr):
            raise WinNotifyError(
                f"{what}: 0x{addr:X} is not a canonical kernel address -- "
                "refusing to send it (the driver would dereference it)")
        return addr

    def _read_packet(self, addr, in_size, bias):
        base = (addr - bias) & 0xFFFFFFFFFFFFFFFF
        packet = base.to_bytes(8, "little") + (0).to_bytes(8, "little")
        return packet.ljust(in_size, b"\x00")[:in_size]

    def read_kernel_qwords(self, addr):
        """One READ IOCTL returns 5 consecutive QWORDs at addr."""
        addr = self._gate_kernel_addr(addr, "kernel read")
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
        addr = self._gate_kernel_addr(addr, "kernel read")
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
        addr = self._gate_kernel_addr(addr, "kernel write")
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
    #
    # SAFETY RULE: this driver dereferences whatever it is given, so a wrong
    # address is an instant bugcheck.  Nothing is ever sent to 0x222040 unless
    # it is a canonical kernel address AND (for EPROCESS pointers) it already
    # passed a sanity check.  Candidate offsets are NEVER blindly probed:
    # only `ps_initial_system_offsets[0]` is used unless the user explicitly
    # sets "probe_ps_offsets": true in winnotify.json.
    def _canon(self, value):
        """Sign-extend a 48-bit canonical address the way the CPU does."""
        value &= 0xFFFFFFFFFFFFFFFF
        if value & 0x0000800000000000:
            value |= 0xFFFF000000000000
        return value

    def _is_kernel_ptr(self, value):
        """$FFFFFFFF80000000..$FFFFFFFFFFFFFFFF (or a canonical high address)."""
        if not value:
            return False
        value &= 0xFFFFFFFFFFFFFFFF
        if value >> 48 == 0xFFFF:
            return True
        # canonical but sign-extended only to bit 47 (KASLR bases below the
        # 0xFFFF800000000000 boundary when sign-extended by the driver)
        return (value & 0xFFFF800000000000) == 0xFFFF800000000000

    def _is_user_ptr(self, value):
        return 0 < value < 0x0000800000000000

    def _looks_like_eprocess(self, addr, pid_off, links_off=None,
                             dtb_off=None):
        """Structurally validate an EPROCESS before trusting its fields.

        Cheap and read-only: a handful of QWORD reads inside one structure.
        A wrong candidate is rejected instead of being dereferenced further.
        """
        if not self._is_kernel_ptr(addr):
            return False
        links_off = self.cfg["eprocess_links"] if links_off is None else links_off
        dtb_off = self.cfg["eprocess_dtb"] if dtb_off is None else dtb_off
        flink = self.read_qword(addr + links_off)
        blink = self.read_qword(addr + links_off + 8)
        if self._is_kernel_ptr(flink) and self._is_kernel_ptr(blink):
            pass
        elif flink == addr + links_off:          # only member of its list
            pass
        else:
            return False
        pfn = self.read_qword(addr + dtb_off) & 0x000FFFFFFFFFF000
        if not (0x1000 <= pfn < 0x000FFFFFFFFFF000):
            return False
        return self.read_qword(addr + pid_off) < 0x1000000

    def _eprocess_layouts(self):
        """(pid, links, dtb) triples to try: the configured one plus opt-in shifts."""
        base = (self.cfg["eprocess_pid"], self.cfg["eprocess_links"],
                self.cfg["eprocess_dtb"])
        found = getattr(self, "_layout", None)
        if found is not None:
            return [found]
        layouts = [base]
        # DirectoryTableBase lives in KPROCESS (start of EPROCESS) and did not
        # move for 24H2; only pid/links/token shifted.  Opt-in: guessing shifts
        # means reading at offsets inside a valid struct, which is safe, but it
        # is still an extra variable -- default off.
        if self.cfg.get("probe_eprocess_shifts", False):
            for shift in self.cfg.get("eprocess_probe_shifts", [0x10]):
                layouts.append((base[0] + shift, base[1] + shift, base[2]))
        return layouts

    def _ps_offsets(self):
        offsets = list(self.cfg["ps_initial_system_offsets"])
        if not self.cfg.get("probe_ps_offsets", False):
            return offsets[:1]
        preferred = self.cfg.get("preferred_ps_offset")
        if preferred is not None:
            offsets = [offset for offset in offsets if offset != preferred]
            offsets.insert(0, preferred)
        return offsets

    def find_system_eprocess(self):
        """Resolve PsInitialSystemProcess with the fewest possible dereferences.

        A wrong offset here points *inside* ntoskrnl's .data, so the value read
        is garbage -> validating it as an EPROCESS fails cleanly instead of
        crashing, and only then is the next candidate tried (opt-in).
        """
        if not self.kernel_base:
            self.get_kernel_base()
        for pid_off, links_off, dtb_off in self._eprocess_layouts():
            for off in self._ps_offsets():
                ptr = self.read_qword(self.kernel_base + off)
                if not self._is_kernel_ptr(ptr):
                    continue
                if self.read_qword(ptr + pid_off) != 4:
                    continue
                if not self._looks_like_eprocess(ptr, pid_off, links_off, dtb_off):
                    continue
                self._layout = (pid_off, links_off, dtb_off)
                self._ps_offset = off
                self._system_eprocess = ptr
                if off != self.cfg["ps_initial_system_offsets"][0]:
                    self.log(f"[i] PsInitialSystemProcess resolved at +0x{off:X}")
                return ptr
        return 0

    def _layout_now(self):
        return getattr(self, "_layout", (
            self.cfg["eprocess_pid"], self.cfg["eprocess_links"],
            self.cfg["eprocess_dtb"]))

    def find_process_eprocess(self, pid, max_iter=None):
        """Walk ActiveProcessLinks, validating every hop before dereferencing."""
        pid = int(pid)
        if pid in self._eprocess_cache:
            return self._eprocess_cache[pid]
        sysproc = self.find_system_eprocess()
        if not sysproc:
            return 0
        pid_off, links, dtb_off = self._layout_now()
        max_iter = max_iter or self.cfg.get("max_process_iter", 2000)
        head = sysproc + links

        current = sysproc
        for _ in range(max_iter):
            flink = self.read_qword(current + links)
            if not self._is_kernel_ptr(flink) or flink == head:
                break
            nxt = flink - links
            if not self._is_kernel_ptr(nxt):
                break
            if self.read_qword(nxt + pid_off) == pid:
                if self._looks_like_eprocess(nxt, pid_off, links, dtb_off):
                    self._eprocess_cache[pid] = nxt
                    return nxt
                break
            current = nxt
        return 0

    def get_process_cr3(self, pid):
        """EPROCESS.DirectoryTableBase, validated (a bad CR3 crashes the driver)."""
        eproc = self.find_process_eprocess(pid)
        if not eproc:
            return 0
        dtb_off = self._layout_now()[2]
        dtb = self.read_qword(eproc + dtb_off)
        pfn = dtb & 0x000FFFFFFFFFF000
        if not (0x1000 <= pfn < self.cfg.get("cr3_max", 0x000FFFFFFFFFF000)):
            return 0
        return pfn

    # -- virtual memory R/W through the target's page tables ---------------
    #
    # Primary path: IOCTL 0x222000 / 0x222004, which take the target DirBase
    # (CR3) and walk the page tables inside the driver.  Those IOCTLs return a
    # status for invalid pages (no bugcheck), which makes them the safe path;
    # the 0x222040/0x222044 fallback dereferences raw kernel VAs and can
    # bugcheck on a bad address, so it is opt-in only.
    def _guard_user_va(self, addr, size):
        """Refuse addresses that would make the driver touch something bad.

        Boot-time quirk (the BSOD): passing a kernel VA here makes the driver
        copy the *kernel* CR3 into the target's DirectoryTableBase; the next
        context switch then runs the process on the kernel page table.
        """
        if not addr:
            raise WinNotifyError("address 0x0 is not mapped -- refusing")
        if addr < 0x10000:
            raise WinNotifyError(
                f"0x{addr:X} is a null-page address -- refusing (nothing mapped there)")
        if addr >= 0x0000800000000000:
            raise WinNotifyError(
                f"0x{addr:X} is a kernel address, not a process virtual address")
        if addr + size > 0x0000800000000000:
            raise WinNotifyError(
                f"0x{addr:X}+0x{size:X} crosses out of user space -- refusing")

    def read_memory(self, pid, addr, size):
        if size < 0:
            raise ValueError("negative size")
        if size == 0:
            return b""
        addr &= 0xFFFFFFFFFFFFFFFF
        self._guard_user_va(addr, size)
        cr3 = self.get_process_cr3(pid)
        if not cr3:
            raise WinNotifyError(
                f"pid {pid}: CR3 not found (unknown process or offset mismatch)")
        if not self.cfg.get("use_direct_vioctl", True):
            return self._read_memory_via_kernel(cr3, addr, size)

        buf = ctypes.create_string_buffer(size)
        ptr = ctypes.addressof(buf)
        page = self.cfg["phys_page_size"]
        step = self.cfg.get("vioctl_chunk", 0x1000)
        done = 0
        while done < size:
            cur = addr + done
            off = cur & (page - 1)
            take = min(page - off, size - done, step)
            try:
                self._vread(cr3, cur, ptr + done, take)      # per-page: safe
            except WinNotifyError as exc:
                raise WinNotifyError(
                    f"page-table read failed at 0x{cur:X} "
                    f"({done} of {size} bytes read): {exc}") from exc
            done += take
        return buf.raw

    def _read_memory_via_kernel(self, cr3, addr, size):
        """UNSAFE, opt-in fallback via 0x222040.

        `addr` must be a *kernel* VA (the only thing 0x222040 can read).  There
        is deliberately no "guess the VA" step: an unmapped address here means
        a bugcheck, so this path is only reachable with
        "use_direct_vioctl": false and an explicitly supplied kernel address.
        """
        if not self._is_kernel_ptr(addr):
            raise WinNotifyError(
                f"0x{addr:X} is not a kernel address -- the 0x222040 fallback "
                "cannot translate process VAs; keep use_direct_vioctl=true")
        if addr + size > 0xFFFFFFFFFFFFFFFF:
            raise WinNotifyError("read range wraps around")
        return self._kernel_read_region(addr, size)

    def _unsafe_kernel_read(self, addr, size):
        """Read kernel VA through 0x222040 with validation (opt-in only)."""
        if not self._is_kernel_ptr(addr):
            raise WinNotifyError(f"0x{addr:X} is not a kernel address")
        return self._kernel_read_region(addr, size)

    def _kernel_read_region(self, addr, size):
        """Up to one page, in 5-QWORD (0x28 byte) strides, via 0x222040."""
        page = self.cfg["phys_page_size"]
        stride = self.cfg["read_qwords"] * 8
        out = bytearray()
        cur = addr
        end = addr + min(size, page)
        while cur < end:
            take = min(stride, end - cur)
            vals = self.read_kernel_qwords(cur)
            raw = b"".join(v.to_bytes(8, "little") for v in vals)
            out += raw[:take]
            cur += take
        return bytes(out)

    def write_memory(self, pid, addr, data):
        data = bytes(data)
        if not data:
            return
        addr &= 0xFFFFFFFFFFFFFFFF
        self._guard_user_va(addr, len(data))
        cr3 = self.get_process_cr3(pid)
        if not cr3:
            raise WinNotifyError(
                f"pid {pid}: CR3 not found (unknown process or offset mismatch)")
        if not self.cfg.get("use_direct_vioctl", True):
            self._write_memory_via_kernel(cr3, addr, data)
            return

        buf = ctypes.create_string_buffer(data, len(data))
        ptr = ctypes.addressof(buf)
        page = self.cfg["phys_page_size"]
        done = 0
        while done < len(data):
            cur = addr + done
            off = cur & (page - 1)
            take = min(page - off, len(data) - done)
            self._vwrite(cr3, cur, ptr + done, take)
            done += take

    def _write_memory_via_kernel(self, cr3, addr, data):
        """UNSAFE fallback: 0x222044 memmove into kernel VAs."""
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
                old = self._kernel_read_region(va_page, page)
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
            if getattr(self, "_started_service", False) and not self.cfg.get(
                    "force_unload", False):
                self.log("[i] keeping the driver service running (stopping a "
                         "driver that was just started can bugcheck; use "
                         "--unload together with \"force_unload\": true to "
                         "force it)")
                return
            try:
                self.unload_driver()
            except WinNotifyError:
                pass


# ---------------------------------------------------------------------------
# Safe address discovery (no kernel address guessing involved)
# ---------------------------------------------------------------------------
class _MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


def module_base_w(module_name=None):
    """Load address of a module in *this* process, via Win32 (not the driver)."""
    _require_windows()
    handle = _api(_k32, "GetModuleHandleW")(module_name)
    if handle is None:
        raise WinNotifyError(f"GetModuleHandleW({module_name}) failed")
    if not isinstance(handle, int):
        handle = ctypes.cast(handle, ctypes.c_void_p).value
    return int(handle or 0)


def self_addresses():
    """Known-good (label, address) pairs inside our own process.

    Everything here comes from the user-mode side (image base, PEB, module
    exports, a fresh allocation), so a selftest built on them never asks the
    driver to dereference a guessed kernel address.
    """
    _require_windows()
    result = []
    try:
        result.append(("image base (MZ)", module_base_w(None)))
    except WinNotifyError:
        pass
    try:
        teb = ctypes.cast(_api(_k32, "NtCurrentTeb")(), ctypes.c_void_p).value
        peb = int.from_bytes(ctypes.string_at(teb + 0x60, 8), "little")
        if peb:
            result.append(("PEB", peb))
    except Exception:
        pass
    try:
        ntdll = ctypes.WinDLL("ntdll")
        nt_close = ntdll.NtClose
        result.append(("ntdll!NtClose", ctypes.cast(nt_close, ctypes.c_void_p).value))
    except Exception:
        pass
    try:
        kernel32 = _load_library("kernel32")
        virtual_alloc = _try_getattr(kernel32, "VirtualAlloc")
        virtual_alloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                  wintypes.DWORD, wintypes.DWORD]
        virtual_alloc.restype = ctypes.c_void_p
        mem = virtual_alloc(None, 0x1000, 0x3000, 0x04)      # RW, 4 KB
        if mem:
            result.append(("fresh 4 KB allocation", int(mem)))
            ctypes.memmove(ctypes.c_void_p(mem), b"WINNOTIFY-SELFTEST", 18)
    except Exception:
        pass
    return [(label, addr) for label, addr in result if addr]


# ---------------------------------------------------------------------------
# Kernel base without the driver (fallback for "0x22200C answered 0")
# ---------------------------------------------------------------------------
def _system_module_information():
    """NtQuerySystemInformation(SystemModuleInformation) from user mode."""
    _require_windows()
    ntdll = _load_library("ntdll")
    query = _try_getattr(ntdll, "NtQuerySystemInformation")
    if query is None:
        raise WinNotifyError("ntdll!NtQuerySystemInformation not available")
    query.argtypes = [ctypes.c_int, ctypes.c_void_p, wintypes.ULONG,
                      ctypes.POINTER(wintypes.ULONG)]
    query.restype = wintypes.LONG
    size = wintypes.ULONG(0)
    query(11, None, 0, ctypes.byref(size))          # 11 = SystemModuleInformation
    if not size.value:
        raise WinNotifyError("module information is empty")
    buf = ctypes.create_string_buffer(size.value)
    status = query(11, buf, size.value, ctypes.byref(size))
    if status < 0:
        raise WinNotifyError(f"NtQuerySystemInformation failed: 0x{status & 0xFFFFFFFF:X}")
    count = ctypes.cast(buf, ctypes.POINTER(wintypes.ULONG))[0]
    entry_size = 0x130
    base = ctypes.addressof(buf) + 8
    modules = []
    for i in range(count):
        off = base + i * entry_size
        if off + entry_size > ctypes.addressof(buf) + size.value:
            break
        raw = ctypes.string_at(off, entry_size)
        dll_base = int.from_bytes(raw[0:8], "little")
        name_bytes = raw[0x28:entry_size].split(b"\x00", 1)[0]
        modules.append((name_bytes.decode("latin-1"), dll_base))
    return modules


def kernel_base_from_system_info(name="ntoskrnl.exe"):
    """Same answer as the driver's 0x22200C, obtained without it."""
    wanted = name.lower()
    for module, base in _system_module_information():
        short = module.replace("\\??\\", "").replace("\\SystemRoot\\", "")
        short = short.split("\\")[-1].lower()
        if short == wanted:
            return base
    raise WinNotifyError(f"{name} not found in the module list")


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
                else:
                    self._started_service = True
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
        self._vet_ioctl_packet(code, payload)
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

    def _vet_ioctl_packet(self, code, payload):
        """Last line of defence before the kernel sees anything.

        The driver trusts every pointer in the request.  A pointer that is not
        in our own process (and not a canonical kernel address where the IOCTL
        expects one) is therefore refused here instead of bugchecking.
        """
        if not self.cfg.get("vet_ioctl_packets", True):
            return
        if code == self.cfg["ioctl_info"]:
            ptr = int.from_bytes(payload[:8].ljust(8, b"\x00"), "little")
            if not self._is_user_ptr(ptr):
                raise WinNotifyError(
                    f"0x{code:X}: +0x00 must be a pointer to the module-name "
                    f"string in our process, got 0x{ptr:X} -- refusing "
                    "(the driver would dereference it)")
        elif code in (self.cfg["ioctl_vread"], self.cfg["ioctl_vwrite"]):
            layout = self.cfg.get("vioctl_layout", 0)
            field = lambda off: int.from_bytes(
                payload[off:off + 8].ljust(8, b"\x00"), "little")
            if layout == 0:            # [flags][va][buf][size][cr3]
                va, buf_ptr, cr3 = field(8), field(0x10), field(0x20)
            else:                      # [cr3][va][size][buf]
                cr3, va, buf_ptr = field(0), field(8), field(0x18)
            if not cr3 and len(payload) == 0x20:
                # legacy struct just sent with the documented layout: the CR3
                # lives at +0x18 there.  Accept either shape for the check --
                # the actual layout is re-detected from the driver's reply.
                alt = field(0x18)
                if 0x1000 <= (alt & 0x000FFFFFFFFFF000) <= 0x000FFFFFFFFFF000:
                    cr3 = alt
            if not self._is_user_ptr(buf_ptr):
                raise WinNotifyError(
                    f"0x{code:X}: data buffer 0x{buf_ptr:X} is not a valid "
                    "user pointer -- refusing")
            if not self._is_user_ptr(va):
                raise WinNotifyError(
                    f"0x{code:X}: 0x{va:X} is not a process virtual address -- "
                    "refusing (a kernel VA here would poison the target CR3)")
            if not (0x1000 <= (cr3 & 0x000FFFFFFFFFF000) <= 0x000FFFFFFFFFF000):
                raise WinNotifyError(
                    f"0x{code:X}: CR3 0x{cr3:X} does not look like a page table")
        elif code == self.cfg["ioctl_write"]:
            src = int.from_bytes(payload[:8].ljust(8, b"\x00"), "little")
            dst = int.from_bytes(payload[0x10:0x18].ljust(8, b"\x00"), "little")
            if not self._is_user_ptr(src):
                raise WinNotifyError(
                    f"0x{code:X}: source 0x{src:X} is not a user pointer -- refusing")
            if not self._is_kernel_ptr(dst):
                raise WinNotifyError(
                    f"0x{code:X}: destination 0x{dst:X} is not a kernel address -- "
                    "refusing")
        elif code == self.cfg["ioctl_read"]:
            base = int.from_bytes(payload[:8].ljust(8, b"\x00"), "little")
            start = (base + self.cfg["read_bias"]) & 0xFFFFFFFFFFFFFFFF
            if not self._is_kernel_ptr(start):
                raise WinNotifyError(
                    f"0x{code:X}: 0x{start:X} is not a kernel address -- refusing")

    # -- kernel base -------------------------------------------------------
    def get_kernel_base(self, autodetect=True):
        """0x22200C: hand the driver a *valid user pointer* to the module name.

        The driver reads a QWORD at +0x00 and uses it as a pointer to the name
        string (it never copies the bytes into the kernel).  Writing the ASCII
        name at +0x00 makes the driver dereference ~0x6C726B736F74746E, i.e. a
        guaranteed bugcheck -- that was the selftest BSOD.  +0x00 is now always
        the address of a string buffer we own.
        """
        in_size = self.cfg["info_in_size"]
        out_size = self.cfg["info_out_size"]
        off = self.cfg["info_result_offset"]
        pointer_mode = self.cfg.get("info_name_is_pointer", True)
        if self.cfg.get("ensure_debug_privilege", True):
            self._ensure_debug_privilege()
        last = None
        for name in self.cfg["info_module_names"]:
            try:
                if pointer_mode:
                    out = self._info_pointer_call(name, in_size, out_size)
                else:
                    packet = (name.encode("ascii") + b"\x00")[:in_size].ljust(
                        in_size, b"\x00")
                    out = self.ioctl(self.cfg["ioctl_info"], packet,
                                     out_size=out_size, in_size=in_size)
            except WinNotifyIoctlError as exc:
                last = exc
                if exc.winerror == ERROR_BAD_LENGTH and pointer_mode:
                    # same semantics, other struct size: retry with a pointer
                    for size in self.cfg.get("info_probe_sizes", [0x18, 0x28]):
                        try:
                            out = self._info_pointer_call(
                                name, size, max(out_size, size))
                        except WinNotifyError:
                            continue
                        cand = int.from_bytes(out[off:off + 8], "little")
                        if cand and self._looks_like_kernel_base(cand):
                            self.cfg["info_in_size"] = size
                            self.cfg["info_out_size"] = max(out_size, size)
                            self.kernel_base = cand
                            self.log(f"[i] module-base IOCTL auto-detected: "
                                     f"pointer, in=0x{size:X}")
                            return cand
                continue
            except WinNotifyError as exc:
                last = exc
                continue
            if len(out) < off + 8:
                last = WinNotifyError("module-base reply was too short")
                continue
            base = int.from_bytes(out[off:off + 8], "little")
            if base and self._looks_like_kernel_base(base):
                self.kernel_base = base
                return base
            if base == 0:
                last = WinNotifyError(
                    "0x22200C answered 0: the driver's module list was empty. "
                    "That happens when SeDebugPrivilege is not enabled in this "
                    "token (run as Administrator) or the driver's internal "
                    "module snapshot failed")
            else:
                last = WinNotifyError(
                    f"module-base reply held 0x{base:X} (not a plausible "
                    "kernel base)")
        if self.cfg.get("fallback_kernel_base", True):
            try:
                base = kernel_base_from_system_info(self.cfg["info_module_names"][0])
                if self._looks_like_kernel_base(base):
                    self.kernel_base = base
                    self.kernel_base_source = "NtQuerySystemInformation"
                    self.log(f"[i] 0x22200C gave nothing ({last}); using "
                             f"NtQuerySystemInformation instead: 0x{base:X}")
                    return base
            except WinNotifyError as exc:
                self.log(f"[!] user-mode module lookup failed too: {exc}")
        if last:
            raise WinNotifyError(f"{last}  [module-base IOCTL layout mismatch?]")
        raise WinNotifyError("driver returned no kernel base")

    def _ensure_debug_privilege(self):
        """The INFO IOCTL goes through ZwQuerySystemInformation(0xb) which
        needs SeDebugPrivilege enabled -- otherwise the driver sees an empty
        module list and returns 0."""
        try:
            present, enabled = privilege_state("SeDebugPrivilege")
        except WinNotifyError:
            return False
        if enabled:
            return True
        if not present:
            self.log("[!] SeDebugPrivilege is not in this token -- run elevated")
            return False
        try:
            enable_privilege("SeDebugPrivilege")
            self.log("[+] SeDebugPrivilege enabled")
            return True
        except WinNotifyError as exc:
            self.log(f"[!] could not enable SeDebugPrivilege: {exc}")
            return False

    def _looks_like_kernel_base(self, value):
        """ntoskrnl is 2 MB aligned and lives in the high half."""
        return (value >> 48) == 0xFFFF and (value & 0x1FFFFF) == 0

    def _info_pointer_call(self, name, in_size, out_size):
        """Send 0x22200C with a pointer to a NUL-terminated name in our memory."""
        buf = ctypes.create_string_buffer(name.encode("ascii"), len(name) + 1)
        packet = (ctypes.addressof(buf).to_bytes(8, "little")
                  + b"\x00" * (in_size - 8))
        return self.ioctl(self.cfg["ioctl_info"], packet[:in_size],
                          out_size=out_size, in_size=in_size)

    # -- arbitrary kernel read / write -------------------------------------
    #
    # Every address below is dereferenced by the driver, so the gate refuses
    # anything that is not a canonical kernel address.  `allow_unknown_ioctl`
    # governs IOCTL *codes* only (a wrong code returns an error, it does not
    # touch memory): keep it True for the shape detection, set it False if you
    # prefer a pure-single-shot run.
    def _gate_kernel_addr(self, addr, what):
        """Nothing but a canonical kernel address may reach 0x222040/0x222044.

        This is unconditional: the driver dereferences the value as-is, so a
        user-mode or non-canonical address here is a one-way ticket to a
        bugcheck.  (`allow_unknown_ioctl` only governs IOCTL *codes*.)
        """
        addr &= 0xFFFFFFFFFFFFFFFF
        if not self._is_kernel_ptr(addr):
            raise WinNotifyError(
                f"{what}: 0x{addr:X} is not a canonical kernel address -- "
                "refusing to send it (the driver would dereference it)")
        return addr

    def _read_packet(self, addr, in_size, bias):
        base = (addr - bias) & 0xFFFFFFFFFFFFFFFF
        packet = base.to_bytes(8, "little") + (0).to_bytes(8, "little")
        return packet.ljust(in_size, b"\x00")[:in_size]

    def read_kernel_qwords(self, addr):
        """One READ IOCTL returns 5 consecutive QWORDs at addr."""
        addr = self._gate_kernel_addr(addr, "kernel read")
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
        addr = self._gate_kernel_addr(addr, "kernel read")
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
        addr = self._gate_kernel_addr(addr, "kernel write")
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
    #
    # SAFETY RULE: this driver dereferences whatever it is given, so a wrong
    # address is an instant bugcheck.  Nothing is ever sent to 0x222040 unless
    # it is a canonical kernel address AND (for EPROCESS pointers) it already
    # passed a sanity check.  Candidate offsets are NEVER blindly probed:
    # only `ps_initial_system_offsets[0]` is used unless the user explicitly
    # sets "probe_ps_offsets": true in winnotify.json.
    def _canon(self, value):
        """Sign-extend a 48-bit canonical address the way the CPU does."""
        value &= 0xFFFFFFFFFFFFFFFF
        if value & 0x0000800000000000:
            value |= 0xFFFF000000000000
        return value

    def _is_kernel_ptr(self, value):
        """$FFFFFFFF80000000..$FFFFFFFFFFFFFFFF (or a canonical high address)."""
        if not value:
            return False
        value &= 0xFFFFFFFFFFFFFFFF
        if value >> 48 == 0xFFFF:
            return True
        # canonical but sign-extended only to bit 47 (KASLR bases below the
        # 0xFFFF800000000000 boundary when sign-extended by the driver)
        return (value & 0xFFFF800000000000) == 0xFFFF800000000000

    def _is_user_ptr(self, value):
        return 0 < value < 0x0000800000000000

    def _looks_like_eprocess(self, addr, pid_off, links_off=None,
                             dtb_off=None):
        """Structurally validate an EPROCESS before trusting its fields.

        Cheap and read-only: a handful of QWORD reads inside one structure.
        A wrong candidate is rejected instead of being dereferenced further.
        """
        if not self._is_kernel_ptr(addr):
            return False
        links_off = self.cfg["eprocess_links"] if links_off is None else links_off
        dtb_off = self.cfg["eprocess_dtb"] if dtb_off is None else dtb_off
        flink = self.read_qword(addr + links_off)
        blink = self.read_qword(addr + links_off + 8)
        if self._is_kernel_ptr(flink) and self._is_kernel_ptr(blink):
            pass
        elif flink == addr + links_off:          # only member of its list
            pass
        else:
            return False
        pfn = self.read_qword(addr + dtb_off) & 0x000FFFFFFFFFF000
        if not (0x1000 <= pfn < 0x000FFFFFFFFFF000):
            return False
        return self.read_qword(addr + pid_off) < 0x1000000

    def _eprocess_layouts(self):
        """(pid, links, dtb) triples to try: the configured one plus opt-in shifts."""
        base = (self.cfg["eprocess_pid"], self.cfg["eprocess_links"],
                self.cfg["eprocess_dtb"])
        found = getattr(self, "_layout", None)
        if found is not None:
            return [found]
        layouts = [base]
        # DirectoryTableBase lives in KPROCESS (start of EPROCESS) and did not
        # move for 24H2; only pid/links/token shifted.  Opt-in: guessing shifts
        # means reading at offsets inside a valid struct, which is safe, but it
        # is still an extra variable -- default off.
        if self.cfg.get("probe_eprocess_shifts", False):
            for shift in self.cfg.get("eprocess_probe_shifts", [0x10]):
                layouts.append((base[0] + shift, base[1] + shift, base[2]))
        return layouts

    def _ps_offsets(self):
        offsets = list(self.cfg["ps_initial_system_offsets"])
        if not self.cfg.get("probe_ps_offsets", False):
            return offsets[:1]
        preferred = self.cfg.get("preferred_ps_offset")
        if preferred is not None:
            offsets = [offset for offset in offsets if offset != preferred]
            offsets.insert(0, preferred)
        return offsets

    def find_system_eprocess(self):
        """Resolve PsInitialSystemProcess with the fewest possible dereferences.

        A wrong offset here points *inside* ntoskrnl's .data, so the value read
        is garbage -> validating it as an EPROCESS fails cleanly instead of
        crashing, and only then is the next candidate tried (opt-in).
        """
        if not self.kernel_base:
            self.get_kernel_base()
        for pid_off, links_off, dtb_off in self._eprocess_layouts():
            for off in self._ps_offsets():
                ptr = self.read_qword(self.kernel_base + off)
                if not self._is_kernel_ptr(ptr):
                    continue
                if self.read_qword(ptr + pid_off) != 4:
                    continue
                if not self._looks_like_eprocess(ptr, pid_off, links_off, dtb_off):
                    continue
                self._layout = (pid_off, links_off, dtb_off)
                self._ps_offset = off
                self._system_eprocess = ptr
                if off != self.cfg["ps_initial_system_offsets"][0]:
                    self.log(f"[i] PsInitialSystemProcess resolved at +0x{off:X}")
                return ptr
        return 0

    def _layout_now(self):
        return getattr(self, "_layout", (
            self.cfg["eprocess_pid"], self.cfg["eprocess_links"],
            self.cfg["eprocess_dtb"]))

    def find_process_eprocess(self, pid, max_iter=None):
        """Walk ActiveProcessLinks, validating every hop before dereferencing."""
        pid = int(pid)
        if pid in self._eprocess_cache:
            return self._eprocess_cache[pid]
        sysproc = self.find_system_eprocess()
        if not sysproc:
            return 0
        pid_off, links, dtb_off = self._layout_now()
        max_iter = max_iter or self.cfg.get("max_process_iter", 2000)
        head = sysproc + links

        current = sysproc
        for _ in range(max_iter):
            flink = self.read_qword(current + links)
            if not self._is_kernel_ptr(flink) or flink == head:
                break
            nxt = flink - links
            if not self._is_kernel_ptr(nxt):
                break
            if self.read_qword(nxt + pid_off) == pid:
                if self._looks_like_eprocess(nxt, pid_off, links, dtb_off):
                    self._eprocess_cache[pid] = nxt
                    return nxt
                break
            current = nxt
        return 0

    def get_process_cr3(self, pid):
        """EPROCESS.DirectoryTableBase, validated (a bad CR3 crashes the driver)."""
        eproc = self.find_process_eprocess(pid)
        if not eproc:
            return 0
        dtb_off = self._layout_now()[2]
        dtb = self.read_qword(eproc + dtb_off)
        pfn = dtb & 0x000FFFFFFFFFF000
        if not (0x1000 <= pfn < self.cfg.get("cr3_max", 0x000FFFFFFFFFF000)):
            return 0
        return pfn

    # -- virtual memory R/W through the target's page tables ---------------
    #
    # Primary path: IOCTL 0x222000 / 0x222004, which take the target DirBase
    # (CR3) and walk the page tables inside the driver.  Those IOCTLs return a
    # status for invalid pages (no bugcheck), which makes them the safe path;
    # the 0x222040/0x222044 fallback dereferences raw kernel VAs and can
    # bugcheck on a bad address, so it is opt-in only.
    def _guard_user_va(self, addr, size):
        """Refuse addresses that would make the driver touch something bad.

        Boot-time quirk (the BSOD): passing a kernel VA here makes the driver
        copy the *kernel* CR3 into the target's DirectoryTableBase; the next
        context switch then runs the process on the kernel page table.
        """
        if not addr:
            raise WinNotifyError("address 0x0 is not mapped -- refusing")
        if addr < 0x10000:
            raise WinNotifyError(
                f"0x{addr:X} is a null-page address -- refusing (nothing mapped there)")
        if addr >= 0x0000800000000000:
            raise WinNotifyError(
                f"0x{addr:X} is a kernel address, not a process virtual address")
        if addr + size > 0x0000800000000000:
            raise WinNotifyError(
                f"0x{addr:X}+0x{size:X} crosses out of user space -- refusing")

    def read_memory(self, pid, addr, size):
        if size < 0:
            raise ValueError("negative size")
        if size == 0:
            return b""
        addr &= 0xFFFFFFFFFFFFFFFF
        self._guard_user_va(addr, size)
        cr3 = self.get_process_cr3(pid)
        if not cr3:
            raise WinNotifyError(
                f"pid {pid}: CR3 not found (unknown process or offset mismatch)")
        if not self.cfg.get("use_direct_vioctl", True):
            return self._read_memory_via_kernel(cr3, addr, size)

        buf = ctypes.create_string_buffer(size)
        ptr = ctypes.addressof(buf)
        page = self.cfg["phys_page_size"]
        step = self.cfg.get("vioctl_chunk", 0x1000)
        done = 0
        while done < size:
            cur = addr + done
            off = cur & (page - 1)
            take = min(page - off, size - done, step)
            try:
                self._vread(cr3, cur, ptr + done, take)      # per-page: safe
            except WinNotifyError as exc:
                raise WinNotifyError(
                    f"page-table read failed at 0x{cur:X} "
                    f"({done} of {size} bytes read): {exc}") from exc
            done += take
        return buf.raw

    def _read_memory_via_kernel(self, cr3, addr, size):
        """UNSAFE, opt-in fallback via 0x222040.

        `addr` must be a *kernel* VA (the only thing 0x222040 can read).  There
        is deliberately no "guess the VA" step: an unmapped address here means
        a bugcheck, so this path is only reachable with
        "use_direct_vioctl": false and an explicitly supplied kernel address.
        """
        if not self._is_kernel_ptr(addr):
            raise WinNotifyError(
                f"0x{addr:X} is not a kernel address -- the 0x222040 fallback "
                "cannot translate process VAs; keep use_direct_vioctl=true")
        if addr + size > 0xFFFFFFFFFFFFFFFF:
            raise WinNotifyError("read range wraps around")
        return self._kernel_read_region(addr, size)

    def _unsafe_kernel_read(self, addr, size):
        """Read kernel VA through 0x222040 with validation (opt-in only)."""
        if not self._is_kernel_ptr(addr):
            raise WinNotifyError(f"0x{addr:X} is not a kernel address")
        return self._kernel_read_region(addr, size)

    def _kernel_read_region(self, addr, size):
        """Up to one page, in 5-QWORD (0x28 byte) strides, via 0x222040."""
        page = self.cfg["phys_page_size"]
        stride = self.cfg["read_qwords"] * 8
        out = bytearray()
        cur = addr
        end = addr + min(size, page)
        while cur < end:
            take = min(stride, end - cur)
            vals = self.read_kernel_qwords(cur)
            raw = b"".join(v.to_bytes(8, "little") for v in vals)
            out += raw[:take]
            cur += take
        return bytes(out)

    def write_memory(self, pid, addr, data):
        data = bytes(data)
        if not data:
            return
        addr &= 0xFFFFFFFFFFFFFFFF
        self._guard_user_va(addr, len(data))
        cr3 = self.get_process_cr3(pid)
        if not cr3:
            raise WinNotifyError(
                f"pid {pid}: CR3 not found (unknown process or offset mismatch)")
        if not self.cfg.get("use_direct_vioctl", True):
            self._write_memory_via_kernel(cr3, addr, data)
            return

        buf = ctypes.create_string_buffer(data, len(data))
        ptr = ctypes.addressof(buf)
        page = self.cfg["phys_page_size"]
        done = 0
        while done < len(data):
            cur = addr + done
            off = cur & (page - 1)
            take = min(page - off, len(data) - done)
            self._vwrite(cr3, cur, ptr + done, take)
            done += take

    def _write_memory_via_kernel(self, cr3, addr, data):
        """UNSAFE fallback: 0x222044 memmove into kernel VAs."""
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
                old = self._kernel_read_region(va_page, page)
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
            if getattr(self, "_started_service", False) and not self.cfg.get(
                    "force_unload", False):
                self.log("[i] keeping the driver service running (stopping a "
                         "driver that was just started can bugcheck; use "
                         "--unload together with \"force_unload\": true to "
                         "force it)")
                return
            try:
                self.unload_driver()
            except WinNotifyError:
                pass


# ---------------------------------------------------------------------------
# Safe address discovery (no kernel address guessing involved)
# ---------------------------------------------------------------------------
class _MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


def module_base_w(module_name=None):
    """Load address of a module in *this* process, via Win32 (not the driver)."""
    _require_windows()
    handle = _api(_k32, "GetModuleHandleW")(module_name)
    if handle is None:
        raise WinNotifyError(f"GetModuleHandleW({module_name}) failed")
    if not isinstance(handle, int):
        handle = ctypes.cast(handle, ctypes.c_void_p).value
    return int(handle or 0)


def self_addresses():
    """Known-good (label, address) pairs inside our own process.

    Everything here comes from the user-mode side (image base, PEB, module
    exports, a fresh allocation), so a selftest built on them never asks the
    driver to dereference a guessed kernel address.
    """
    _require_windows()
    result = []
    try:
        result.append(("image base (MZ)", module_base_w(None)))
    except WinNotifyError:
        pass
    try:
        teb = ctypes.cast(_api(_k32, "NtCurrentTeb")(), ctypes.c_void_p).value
        peb = int.from_bytes(ctypes.string_at(teb + 0x60, 8), "little")
        if peb:
            result.append(("PEB", peb))
    except Exception:
        pass
    try:
        ntdll = ctypes.WinDLL("ntdll")
        nt_close = ntdll.NtClose
        result.append(("ntdll!NtClose", ctypes.cast(nt_close, ctypes.c_void_p).value))
    except Exception:
        pass
    try:
        kernel32 = _load_library("kernel32")
        virtual_alloc = _try_getattr(kernel32, "VirtualAlloc")
        virtual_alloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                  wintypes.DWORD, wintypes.DWORD]
        virtual_alloc.restype = ctypes.c_void_p
        mem = virtual_alloc(None, 0x1000, 0x3000, 0x04)      # RW, 4 KB
        if mem:
            result.append(("fresh 4 KB allocation", int(mem)))
            ctypes.memmove(ctypes.c_void_p(mem), b"WINNOTIFY-SELFTEST", 18)
    except Exception:
        pass
    return [(label, addr) for label, addr in result if addr]


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
