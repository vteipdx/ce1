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

DEFAULT_DRIVER_NAME = "WinNotify"
DEFAULT_DEVICE_PATH = r"\\.\WinNotify"


# ---------------------------------------------------------------------------
# Default profile -- identical numbers to src/PhysicalMemory.pas
# ---------------------------------------------------------------------------
DEFAULT_CONFIG = {
    "ioctl_info": 0x22200C,
    "ioctl_read": 0x222040,
    "ioctl_write": 0x222044,
    "ioctl_phys_read": 0x222050,
    "ioctl_phys_write": 0x222054,
    "device_path": DEFAULT_DEVICE_PATH,
    "service_name": DEFAULT_DRIVER_NAME,
    "driver_search": [
        r"C:\Windows\System32\drivers\WinNotify.sys",
        "exe_dir\\WinNotify.sys",
        "exe_dir\\signeddrv.sys",
        r"C:\Windows\System32\drivers\signeddrv.sys",
    ],
    "info_module_names": ["ntoskrnl.exe", "ntoskrnl"],
    "info_input_size": 256,
    "info_output_size": 64,
    "info_result_offset": 0x10,
    "read_input_size": 56,
    "read_bias": 0x10,
    "read_output_size": 64,
    "read_result_offset": 0x20,
    "write_input_size": 24,
    "phys_header_size": 20,
    "phys_page_size": 0x1000,
    "eprocess_links": 0x448,
    "eprocess_pid": 0x440,
    "eprocess_dtb": 0x28,
    "ps_initial_system_offsets": [0xCFC420, 0xD19420, 0xD0A420, 0xCFC3E0],
    "cr3_mask": 0x000FFFFFFFFFF000,
    "keep_service": True,
}

_INT_KEYS = {
    "ioctl_info", "ioctl_read", "ioctl_write", "ioctl_phys_read",
    "ioctl_phys_write", "info_input_size", "info_output_size",
    "info_result_offset", "read_input_size", "read_bias",
    "read_output_size", "read_result_offset", "write_input_size",
    "phys_header_size", "phys_page_size", "eprocess_links", "eprocess_pid",
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
    def ioctl(self, code, in_buf=b"", out_size=0):
        """Return the raw output buffer (Pascal code ignores bytesReturned)."""
        _require_windows()
        if not self.device:
            raise WinNotifyError("device is not open")
        in_arr = ctypes.create_string_buffer(bytes(in_buf), max(len(in_buf), 1))
        out_arr = ctypes.create_string_buffer(out_size) if out_size else None
        returned = wintypes.DWORD(0)
        ok = _api(_k32, "DeviceIoControl")(
            self.device, code, in_arr, len(in_buf),
            out_arr, out_size, ctypes.byref(returned), None,
        )
        if not ok:
            raise _winerr(f"DeviceIoControl(0x{code:X})")
        return out_arr.raw if out_arr is not None else b""

    # -- kernel base -------------------------------------------------------
    def get_kernel_base(self):
        off = self.cfg["info_result_offset"]
        for name in self.cfg["info_module_names"]:
            in_buf = name.encode("ascii").ljust(
                max(self.cfg["info_input_size"], len(name) + 1), b"\x00"
            )
            out = self.ioctl(self.cfg["ioctl_info"], in_buf,
                             self.cfg["info_output_size"])
            if len(out) >= off + 8:
                base = int.from_bytes(out[off:off + 8], "little")
                if base:
                    self.kernel_base = base
                    return base
        raise WinNotifyError("driver returned no kernel base")

    # -- arbitrary kernel QWORD -------------------------------------------
    def read_qword(self, addr):
        bias = self.cfg["read_bias"]
        in_buf = ((addr - bias) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        in_buf += b"\x00" * 8
        in_buf = in_buf.ljust(self.cfg["read_input_size"], b"\x00")
        out = self.ioctl(self.cfg["ioctl_read"], in_buf,
                         self.cfg["read_output_size"])
        off = self.cfg["read_result_offset"]
        if len(out) < off + 8:
            return 0
        return int.from_bytes(out[off:off + 8], "little")

    def write_qword(self, addr, value):
        # packet {src_ptr(8), size(8), dst_ptr(8)} -> kernel memmove(dst, src, 8)
        src = ctypes.c_uint64(value & 0xFFFFFFFFFFFFFFFF)
        in_buf = (
            ctypes.addressof(src).to_bytes(8, "little")
            + (8).to_bytes(8, "little")
            + (addr & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        ).ljust(self.cfg["write_input_size"], b"\x00")
        self.ioctl(self.cfg["ioctl_write"], in_buf, 0)

    # -- physical R/W via DirBase -----------------------------------------
    def _phys_page_read(self, cr3, va_page, size=None):
        size = size or self.cfg["phys_page_size"]
        header = (
            (cr3 & self.cfg["cr3_mask"]).to_bytes(8, "little")
            + (va_page & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
            + size.to_bytes(4, "little")
        ).ljust(self.cfg["phys_header_size"], b"\x00")
        return self.ioctl(self.cfg["ioctl_phys_read"], header, size)

    def _phys_page_write(self, cr3, va_page, data):
        header = (
            (cr3 & self.cfg["cr3_mask"]).to_bytes(8, "little")
            + (va_page & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
            + len(data).to_bytes(4, "little")
        ).ljust(self.cfg["phys_header_size"], b"\x00")
        self.ioctl(self.cfg["ioctl_phys_write"], header + data, 0)

    # -- EPROCESS navigation ----------------------------------------------
    def find_system_eprocess(self):
        if not self.kernel_base:
            self.get_kernel_base()
        for off in self.cfg["ps_initial_system_offsets"]:
            ptr = self.read_qword(self.kernel_base + off)
            if not ptr:
                continue
            if self.read_qword(ptr + self.cfg["eprocess_pid"]) == 4:
                return ptr
        return 0

    def find_process_eprocess(self, pid, max_iter=2000):
        pid = int(pid)
        if pid in self._eprocess_cache:
            return self._eprocess_cache[pid]
        links = self.cfg["eprocess_links"]
        sysproc = self.find_system_eprocess()
        if not sysproc:
            return 0
        current = sysproc
        for _ in range(max_iter):
            flink = self.read_qword(current + links)
            if not flink:
                return 0
            current = flink - links
            if self.read_qword(current + self.cfg["eprocess_pid"]) == pid:
                self._eprocess_cache[pid] = current
                return current
            if current == sysproc:
                break
        return 0

    def get_process_cr3(self, pid):
        eproc = self.find_process_eprocess(pid)
        if not eproc:
            return 0
        dtb = self.read_qword(eproc + self.cfg["eprocess_dtb"])
        return dtb & self.cfg["cr3_mask"]

    # -- virtual memory R/W through the target's page tables ---------------
    def read_memory(self, pid, addr, size):
        if size < 0:
            raise ValueError("negative size")
        cr3 = self.get_process_cr3(pid)
        if not cr3:
            raise WinNotifyError(f"pid {pid}: CR3 not found (unknown process?)")
        page = self.cfg["phys_page_size"]
        addr &= 0xFFFFFFFFFFFFFFFF
        out = bytearray()
        done = 0
        while done < size:
            cur = addr + done
            off = cur & (page - 1)
            take = min(page - off, size - done)
            chunk = self._phys_page_read(cr3, cur & ~(page - 1))
            if len(chunk) < page:
                raise WinNotifyError(
                    f"read 0x{cur:X}: driver returned {len(chunk)} bytes")
            out += chunk[off:off + take]
            done += take
        return bytes(out)

    def write_memory(self, pid, addr, data):
        data = bytes(data)
        cr3 = self.get_process_cr3(pid)
        if not cr3:
            raise WinNotifyError(f"pid {pid}: CR3 not found (unknown process?)")
        page = self.cfg["phys_page_size"]
        addr &= 0xFFFFFFFFFFFFFFFF
        done = 0
        while done < len(data):
            cur = addr + done
            off = cur & (page - 1)
            take = min(page - off, len(data) - done)
            va_page = cur & ~(page - 1)
            if off == 0 and take == page:
                buf = data[done:done + take]
            else:
                # read-modify-write: keep the rest of the page intact
                pagebuf = bytearray(self._phys_page_read(cr3, va_page))
                if len(pagebuf) < page:
                    raise WinNotifyError(
                        f"write 0x{cur:X}: page read returned {len(pagebuf)} bytes")
                pagebuf[off:off + take] = data[done:done + take]
                buf = bytes(pagebuf)
            self._phys_page_write(cr3, va_page, buf)
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
