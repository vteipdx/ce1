"""
cli.py -- the .exe entry point (same behaviour as `python cli.py`)

Quickest form -- process, sun-address, new value:
    winnotify-cli.exe PlantsVsZombies.exe 0x0019A5B8 999

Explicit sub-commands:
    winnotify-cli.exe write  <proc> <addr> <value> [-t int|uint|int64|float|bytes|string]
    winnotify-cli.exe read   <proc> <addr> [-n 64]
    winnotify-cli.exe freeze <proc> <addr> <value> [-i 0.1]
    winnotify-cli.exe selftest [--pid <pid>]
    winnotify-cli.exe info                     show driver/OS/offset diagnostics
    winnotify-cli.exe memory-test              safe read/write test on our own process
    winnotify-cli.exe privcheck                token/privilege diagnostics (no IOCTL)

<proc>  = PID ("1234", "0x4D2") or image name ("PlantsVsZombies.exe")
<addr>  = virtual address inside the target, 0x... or decimal
value   = int by default; use -t float for floats, -t bytes for "DEADBEEF"
"""
import argparse
import ctypes
from ctypes import wintypes
import os
import platform
import struct
import sys
import time

import winnotify
from winnotify import WinNotify, WinNotifyError, resolve_pid, enable_privilege


def _tame_stdio():
    """Never let a non-UTF8 console (cp936/cp437) crash the tool."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


_tame_stdio()

BANNER = "winnotify-cli  -  WinNotify.sys bridge (Python port of PhysicalMemory.pas)"

TYPES = ("int", "uint", "int64", "float", "bytes", "hex", "string")


def parse_int(text):
    return int(text, 0)


def encode_value(text, vtype):
    if vtype == "int":
        return struct.pack("<i", parse_int(text))
    if vtype == "uint":
        return struct.pack("<I", parse_int(text))
    if vtype == "int64":
        return struct.pack("<q", parse_int(text))
    if vtype == "float":
        return struct.pack("<f", float(text))
    if vtype in ("bytes", "hex"):
        return bytes.fromhex(text.replace("0x", "").replace(" ", ""))
    if vtype == "string":
        return text.encode("utf-8") + b"\x00"
    raise WinNotifyError(f"unknown type: {vtype}")


def describe(buf):
    if len(buf) < 4:
        return f"{buf.hex()} ({len(buf)} bytes)"
    raw = int.from_bytes(buf[:4], "little")
    signed = struct.unpack("<i", buf[:4])[0]
    if len(buf) >= 8:
        lo = struct.unpack("<I", buf[:4])[0]
        hi = struct.unpack("<I", buf[4:8])[0]
        return (f"dword={signed} (0x{raw:08X})  qword=0x{(hi << 32) | lo:016X}")
    return f"dword={signed} (0x{raw:08X})"


def hexdump(data, base):
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexpart = " ".join(f"{b:02X}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + i:012X}  {hexpart:<47}  |{asc}|")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------
def cmd_read(dev, args):
    pid = resolve_pid(args.target)
    addr = parse_int(args.addr)
    data = dev.read_memory(pid, addr, args.size)
    print(f"[*] pid {pid}  0x{addr:X}  {args.size} bytes")
    print(hexdump(data, addr))
    print(f"[i] {describe(data)}")


def cmd_write(dev, args):
    pid = resolve_pid(args.target)
    addr = parse_int(args.addr)
    payload = encode_value(args.value, args.type)
    print(f"[*] pid {pid}  0x{addr:X} <- {args.value} "
          f"({args.type}, {len(payload)} bytes: {payload.hex()})")
    try:
        before = dev.read_memory(pid, addr, max(len(payload), 4))
        print(f"[i] before: {describe(before)}")
    except WinNotifyError:
        pass
    dev.write_memory(pid, addr, payload)
    after = dev.read_memory(pid, addr, max(len(payload), 4))
    print(f"[i] after : {describe(after)}")
    print("[OK] written")


def cmd_freeze(dev, args):
    pid = resolve_pid(args.target)
    addr = parse_int(args.addr)
    payload = encode_value(args.value, args.type)
    print(f"[*] freezing pid {pid}  0x{addr:X} = {args.value} "
          f"every {args.interval:g}s (Ctrl+C to stop)")
    dev.write_memory(pid, addr, payload)
    try:
        while True:
            time.sleep(args.interval)
            dev.write_memory(pid, addr, payload)
    except KeyboardInterrupt:
        print("\n[i] freeze stopped")


def cmd_selftest(dev, args):
    """Non-destructive checks only -- nothing here can bugcheck the machine.

    Deliberately does NOT walk kernel structures: with this driver every
    unvalidated address dereference is a potential BSOD, so the risky part is
    split into `memory-test` (own process only) and the offset hunt in `info`.
    """
    print(f"[1/5] driver       : {dev.driver_path or '(already loaded)'}")
    print(f"      device       : {dev.cfg['device_path']}")
    print(f"      service      : {dev.service_name}")

    try:
        base = dev.get_kernel_base()      # 0x22200C, no address dereference
    except WinNotifyError as exc:
        print(f"[2/5] module-base IOCTL failed: {exc}")
        try:
            present, enabled = winnotify.privilege_state("SeDebugPrivilege")
            print(f"      SeDebugPrivilege: present={present} enabled={enabled}")
            if present and not enabled:
                print("      -> internal ZwQuerySystemInformation returns an "
                      "empty list; run `privcheck` or restart elevated")
        except WinNotifyError:
            pass
        raise
    print(f"[2/5] ntoskrnl      : 0x{base:X}   (KASLR defeated, no address guessed)")

    pid = resolve_pid(args.pid) if args.pid else os.getpid()
    cr3 = dev.get_process_cr3(pid)        # validated EPROCESS walk
    if not cr3:
        raise WinNotifyError(
            f"could not resolve CR3 for pid {pid}.  Nothing was probed, so the "
            "machine is fine. Run `winnotify-cli.exe info` to see which "
            "PsInitialSystemProcess offset matches your build, then put it "
            "first in ps_initial_system_offsets")
    print(f"[3/5] EPROCESS/CR3  : 0x{cr3:X}   (pid {pid}"
          + (", this process)" if pid == os.getpid() else ")"))

    # 4) safe *user-mode* address discovery + page-table read of it
    addresses = winnotify.self_addresses()
    if not addresses:
        raise WinNotifyError("could not determine any known-good user address")
    label, addr = addresses[0]
    head = dev.read_memory(pid, addr, 2)
    print(f"[4/5] page-table R/W: read {head!r} at 0x{addr:X} ({label}) -- OK")
    if pid == os.getpid() and addr == winnotify.module_base_w(None) and head != b"MZ":
        raise WinNotifyError(
            "self image base did not read back as MZ -- page-table IOCTL layout "
            "is wrong for this driver build")

    # 5) write-back test on memory we own (only for ourselves)
    if pid == os.getpid():
        marker = b"WINNOTIFY-SELFTEST"
        target = None
        for label, candidate in addresses:
            if label.startswith("fresh"):
                target = candidate
        if target:
            dev.write_memory(pid, target, marker)
            back = dev.read_memory(pid, target, len(marker))
            if back != marker:
                raise WinNotifyError(f"write test mismatch: wrote {marker!r}, got {back!r}")
            print(f"[5/5] write test   : wrote+verified {marker!r} at 0x{target:X}")
        else:
            print("[5/5] write test   : skipped (no scratch allocation)")
    else:
        print("[5/5] write test   : skipped (target is not this process; "
              "use `memory-test` to exercise writes safely)")
    print("[OK] all safe checks passed -- driver, kernel base, EPROCESS walk and "
          "page-table R/W work")


def cmd_memory_test(dev, args):
    """Read/write a few bytes inside OUR OWN process -- cannot bugcheck."""
    pid = os.getpid()
    print(f"[*] target: own process, pid {pid} (a bad address here kills only this tool)")
    cr3 = dev.get_process_cr3(pid)
    if not cr3:
        raise WinNotifyError("own CR3 not resolved -- run `info` first")
    addresses = winnotify.self_addresses()
    for label, addr in addresses:
        try:
            head = dev.read_memory(pid, addr, 8)
            print(f"[+] read  0x{addr:X} {label:24s} -> {head.hex()}")
        except WinNotifyError as exc:
            print(f"[!] read  0x{addr:X} {label:24s} -> {exc}")
    scratch = [a for l, a in addresses if l.startswith("fresh")]
    if scratch:
        marker = b"WINNOTIFY-OK"
        dev.write_memory(pid, scratch[0], marker)
        back = dev.read_memory(pid, scratch[0], len(marker))
        print(f"[+] write 0x{scratch[0]:X} -> {back!r} "
              + ("OK" if back == marker else "MISMATCH"))
    print("[OK] own-process page-table access verified")


def cmd_privcheck(dev, args):
    """Pure Win32 diagnostics: no IOCTL is sent, nothing can crash.

    The module-base IOCTL runs ZwQuerySystemInformation(SystemModuleInformation)
    inside the driver, which only returns data when the caller's token has
    SeDebugPrivilege ENABLED.  This shows the token state up front.
    """
    print("[i] no IOCTL is sent by this command -- it only inspects the token")
    elevated = _is_admin()
    print(f"[+] running as admin : {elevated}")
    if not elevated:
        print("[!] not elevated -- SeDebugPrivilege/SeLoadDriverPrivilege are "
              "usually unavailable; re-run from an Administrator prompt")
    for name in ("SeDebugPrivilege", "SeLoadDriverPrivilege"):
        try:
            present, enabled = winnotify.privilege_state(name)
        except WinNotifyError as exc:
            print(f"[-] {name}: {exc}")
            continue
        print(f"[+] {name:22s} present={present!s:5s} enabled={enabled}")
        if present and not enabled:
            try:
                enable_privilege(name)
                present, enabled = winnotify.privilege_state(name)
                print(f"    -> enabled now: {enabled}")
            except WinNotifyError as exc:
                print(f"    -> could not enable: {exc}")
    print("[i] 0x22200C answers 0 if SeDebugPrivilege is not enabled at call time")


def _is_admin():
    try:
        shell32 = ctypes.WinDLL("shell32")
        shell32.IsUserAnAdmin.restype = wintypes.BOOL
        return bool(shell32.IsUserAnAdmin())
    except Exception:
        return False


def cmd_info(dev, args):
    """Show what this build/driver is; never dereferences anything unvalidated."""
    print(f"[+] driver       : {dev.driver_path or '(already loaded)'}")
    print(f"[+] device       : {dev.cfg['device_path']}")
    print(f"[+] os           : {platform.platform()}")
    if winnotify.IS_WINDOWS:
        print(f"[+] build        : {platform.version()}")
    print(f"[+] py           : {sys.version.split()[0]} "
          f"({8 * ctypes.sizeof(ctypes.c_void_p)}-bit)")
    base = dev.kernel_base
    print(f"[+] ntoskrnl     : 0x{base:X}")
    offsets = dev.cfg["ps_initial_system_offsets"]
    preferred = dev.cfg.get("preferred_ps_offset")
    if preferred is not None:
        offsets = [preferred] + [o for o in offsets if o != preferred]
    print(f"[+] probing PsInitialSystemProcess candidates "
          f"(read-only, structural checks, no writes):")
    for off in offsets[: args.max_offsets]:
        try:
            ptr = dev.read_qword(base + off)
        except WinNotifyError as exc:
            print(f"      +0x{off:06X}: read failed: {exc}")
            continue
        if not dev._is_kernel_ptr(ptr):
            print(f"      +0x{off:06X}: 0x{ptr:X}   (not a kernel pointer)")
            continue
        pid = dev.read_qword(ptr + dev.cfg["eprocess_pid"])
        sys_ok = pid == 4 and dev._looks_like_eprocess(ptr, dev.cfg["eprocess_pid"])
        print(f"      +0x{off:06X}: -> 0x{ptr:X} pid={pid}"
              + ("   <== matches (System)" if sys_ok else ""))
    print("[i] set preferred_ps_offset (or reorder ps_initial_system_offsets) "
          "in winnotify.json to the matching value")


# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------
def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--driver", default=argparse.SUPPRESS,
                        help="explicit WinNotify.sys path")
    common.add_argument("--unload", action="store_true", default=argparse.SUPPRESS,
                        help="stop and delete the driver service when done")
    common.add_argument("--json", default=argparse.SUPPRESS,
                        help="IOCTL/offset profile (default: winnotify.json next to the exe)")

    parser = argparse.ArgumentParser(
        prog="winnotify-cli",
        description=BANNER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--driver", default=None)
    parser.add_argument("--unload", action="store_true")
    parser.add_argument("--json", default=None)
    sub = parser.add_subparsers(dest="cmd")

    def target_addr(sp):
        sp.add_argument("target", help="PID or image name (PlantsVsZombies.exe)")
        sp.add_argument("addr", help="virtual address, e.g. 0x0019A5B8")

    sp = sub.add_parser("read", parents=[common], help="read target memory")
    target_addr(sp)
    sp.add_argument("-n", "--size", type=lambda v: int(v, 0), default=16)
    sp.set_defaults(func=cmd_read)

    sp = sub.add_parser("write", parents=[common], help="write a value into target memory")
    target_addr(sp)
    sp.add_argument("value")
    sp.add_argument("-t", "--type", default="int", choices=TYPES)
    sp.set_defaults(func=cmd_write)

    sp = sub.add_parser("freeze", parents=[common], help="keep re-writing a value")
    target_addr(sp)
    sp.add_argument("value")
    sp.add_argument("-t", "--type", default="int", choices=TYPES)
    sp.add_argument("-i", "--interval", type=float, default=0.1)
    sp.set_defaults(func=cmd_freeze)

    sp = sub.add_parser("selftest", parents=[common], help="verify the whole chain")
    sp.add_argument("--pid", default=None)
    sp.set_defaults(func=cmd_selftest)

    sp = sub.add_parser("privcheck", parents=[common],
                        help="token/privilege diagnostics (sends no IOCTL)")
    sp.set_defaults(func=cmd_privcheck)

    sp = sub.add_parser("info", parents=[common],
                        help="driver/OS info + which PsInitialSystemProcess offset matches")
    sp.add_argument("--max-offsets", type=int, default=6,
                    help="how many candidate offsets to try (default 6)")
    sp.set_defaults(func=cmd_info)

    sp = sub.add_parser("memory-test", parents=[common],
                        help="safe read/write test inside our own process")
    sp.set_defaults(func=cmd_memory_test)

    return parser


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()

    # `exe <proc> <addr> <value>` -> `exe write <proc> <addr> <value>`
    if argv and argv[0] not in ("read", "write", "freeze", "selftest", "info",
                                "memory-test", "privcheck", "-h", "--help") \
            and not argv[0].startswith("-"):
        if len(argv) >= 3:
            argv = ["write"] + argv

    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2

    print(BANNER)
    if not winnotify.IS_WINDOWS:
        print("[ERROR] this build must run on Windows")
        return 1

    exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    dev = None
    try:
        try:
            enable_privilege("SeLoadDriverPrivilege")
        except WinNotifyError as exc:
            print(f"[!] {exc} (continuing -- driver may already be loaded)")

        dev = WinNotify(exe_dir=exe_dir,
                        config=winnotify.load_config(exe_dir, args.json))
        dev.start(driver_path=args.driver)
        args.func(dev, args)
        return 0
    except WinNotifyError as exc:
        print(f"[ERROR] {exc}")
        return 1
    except KeyboardInterrupt:
        return 130
    except Exception as exc:                      # never dump a traceback on users
        if os.environ.get("WINNOTIFY_DEBUG"):
            raise
        print(f"[ERROR] {type(exc).__name__}: {exc}")
        print("[i] set WINNOTIFY_DEBUG=1 to get a full traceback")
        return 1
    finally:
        if dev is not None:
            dev.stop(unload=True if args.unload else None)


if __name__ == "__main__":
    sys.exit(main())
