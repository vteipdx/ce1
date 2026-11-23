"""
cli.py -- the .exe entry point (same behaviour as `python cli.py`)

Quickest form -- process, sun-address, new value:
    winnotify-cli.exe PlantsVsZombies.exe 0x0019A5B8 999

Explicit sub-commands:
    winnotify-cli.exe write  <proc> <addr> <value> [-t int|uint|int64|float|bytes|string]
    winnotify-cli.exe read   <proc> <addr> [-n 64]
    winnotify-cli.exe freeze <proc> <addr> <value> [-i 0.1]
    winnotify-cli.exe selftest [--pid <pid>]

<proc>  = PID ("1234", "0x4D2") or image name ("PlantsVsZombies.exe")
<addr>  = virtual address inside the target, 0x... or decimal
value   = int by default; use -t float for floats, -t bytes for "DEADBEEF"
"""
import argparse
import ctypes
import os
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
    print(f"[+] driver     : {dev.driver_path or '(already loaded)'}")
    print(f"[+] device     : {dev.cfg['device_path']}")
    print(f"[+] service    : {dev.service_name}")
    print(f"[+] ntoskrnl   : 0x{dev.kernel_base:X}")
    eproc = dev.find_system_eprocess()
    print(f"[+] System EPROCESS: 0x{eproc:X}" if eproc else "[!] System EPROCESS not found")
    if not eproc:
        raise WinNotifyError("EPROCESS walk failed -- fix offsets in winnotify.json")
    if args.pid:
        pid = resolve_pid(args.pid)
    else:
        # test against ourselves: always present and harmless
        pid = os.getpid()
    print(f"[+] test pid   : {pid}"
          + (" (this process)" if pid == os.getpid() else ""))
    cr3 = dev.get_process_cr3(pid)
    print(f"[+] CR3        : 0x{cr3:X}")
    if not cr3:
        raise WinNotifyError("CR3 lookup failed -- fix eprocess_dtb in winnotify.json")
    base = winnotify._host_dll()
    head = dev.read_memory(pid, base, 2)
    if head != b"MZ":
        raise WinNotifyError(f"self-read through CR3 failed, got {head!r}")
    print("[+] self-read through CR3 page tables: OK (MZ header)")
    print("[OK] bridge operational -- driver load, kernel R/W and process R/W all work")


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

    return parser


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()

    # `exe <proc> <addr> <value>` -> `exe write <proc> <addr> <value>`
    if argv and argv[0] not in ("read", "write", "freeze", "selftest",
                                "-h", "--help") and not argv[0].startswith("-"):
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
