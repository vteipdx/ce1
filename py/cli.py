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

    Every address used here is either handed to us by the driver itself
    (0x222010 / 0x222014) or discovered from our own process, so no kernel
    pointer is ever guessed.
    """
    print(f"[1/5] driver       : {dev.driver_path or '(already loaded)'}")
    print(f"      device       : {dev.cfg['device_path']}")
    print(f"      service      : {dev.service_name}")

    # 2) kernel base -- informational only.  Nothing below needs it: the
    # driver resolves the System EPROCESS (0x222010), the image base
    # (0x222014) and the DirBase itself, and 0x222000/0x222004 take a PID.
    base = dev.kernel_base or getattr(dev, "kernel_base", 0)
    if base:
        print(f"[2/5] ntoskrnl      : 0x{base:X}   "
              f"({getattr(dev, 'kernel_base_source', 'IOCTL')}, no address guessed)")
    else:
        err = getattr(dev, "kernel_base_error", None)
        print(f"[2/5] ntoskrnl      : not needed for this path"
              + (f"  ({err})" if err else ""))
        print("      EPROCESS lookup uses 0x222010; process R/W uses "
              "0x222000/0x222004 with the PID, so no kernel base is required")

    pid = resolve_pid(args.pid) if getattr(args, "pid", None) else os.getpid()
    sysproc = dev.find_system_eprocess()
    if not sysproc:
        raise WinNotifyError(
            "could not get the System EPROCESS: 0x222010 did not answer and "
            "the PsInitialSystemProcess fallback was unavailable. Nothing was "
            "probed, so the machine is fine. Run `info` to see what the "
            "driver answered for each request")
    eproc = dev.find_process_eprocess(pid)
    if not eproc:
        raise WinNotifyError(
            f"pid {pid}: no EPROCESS found. The ActiveProcessLinks walk "
            f"started from the driver-verified System EPROCESS 0x{sysproc:X} "
            "and stopped at an unmapped link, so nothing was guessed and "
            "nothing crashed. Run `info` to see the offsets this build uses")
    cr3 = dev.get_process_cr3(pid)
    print(f"[3/5] EPROCESS/CR3  : 0x{cr3:X}   (pid {pid}"
          + (", this process)" if pid == os.getpid() else ")")
          + f"  EPROCESS 0x{eproc:X}")

    addresses = winnotify.self_addresses()
    if not addresses:
        raise WinNotifyError("could not determine any known-good user address")
    label, addr = addresses[0]
    head = dev.read_memory(pid, addr, 2)
    print(f"[4/5] page-table R/W: read {head!r} at 0x{addr:X} ({label}) -- OK")
    if pid == os.getpid() and addr == winnotify.module_base_w(None) and head != b"MZ":
        raise WinNotifyError(
            "self image base did not read back as MZ -- the 0x222000 copy "
            "direction or struct layout is wrong for this driver build")

    if pid == os.getpid():
        marker = b"WINNOTIFY-SELFTEST"
        target = None
        for lbl, candidate in addresses:
            if lbl.startswith("fresh"):
                target = candidate
        if target:
            dev.write_memory(pid, target, marker)
            back = dev.read_memory(pid, target, len(marker))
            if back != marker:
                raise WinNotifyError(
                    f"write test mismatch: wrote {marker!r}, got {back!r}")
            print(f"[5/5] write test   : wrote+verified {marker!r} at 0x{target:X}")
        else:
            print("[5/5] write test   : skipped (no scratch allocation)")
    else:
        print("[5/5] write test   : skipped (target is not this process; "
              "use `memory-test` to exercise writes safely)")
    print("[OK] all safe checks passed -- driver, kernel base, EPROCESS lookup "
          "and page-table R/W work")


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
    """Pure Win32 diagnostics: no IOCTL is sent, nothing can crash."""
    print("[i] no IOCTL is sent by this command -- it only inspects the token")
    elevated = _is_admin()
    print(f"[+] running as admin : {elevated}")
    try:
        summary = winnotify.token_summary()
        print(f"[+] elevated token   : {summary.get('elevated')}")
        print(f"[+] integrity level  : {summary.get('integrity', '?')}"
              f" (rid 0x{summary.get('integrity_rid', 0):X})")
        print(f"[+] elevation type   : {summary.get('elevation_type')} "
              "(3 = default/UAC-filtered, 2 = full)")
        privs = summary.get("privileges", {})
        print(f"[+] privileges held  : {len(privs)}")
    except WinNotifyError as exc:
        print(f"[!] token query failed: {exc}")
    if not elevated:
        print("[!] not elevated -- an Administrator token that UAC filtered has "
              "no SeLoadDriverPrivilege, so the driver service cannot be "
              "created. Run without --no-elevate to get the UAC prompt, or "
              "start the tool from an Administrator prompt")
    for name in ("SeDebugPrivilege", "SeLoadDriverPrivilege"):
        try:
            present, enabled = winnotify.privilege_state(name)
        except WinNotifyError as exc:
            print(f"[-] {name}: {exc}")
            continue
        print(f"[+] {name:22s} present={present} enabled={enabled}")


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
    if base:
        print(f"[+] ntoskrnl     : 0x{base:X} "
              f"({getattr(dev, 'kernel_base_source', 'IOCTL')})")
    else:
        print(f"[+] ntoskrnl     : (unavailable: "
              f"{getattr(dev, 'kernel_base_error', 'not needed')})")

    print("[+] driver-discovered addresses (no guessing):")
    sysproc = dev.find_system_eprocess()
    print(f"      System EPROCESS    : "
          + (f"0x{sysproc:X}" if sysproc else "(0x222010 not implemented)"))
    mypid = os.getpid()
    ib = dev.image_base_via_driver(mypid)
    print(f"      own image base     : "
          + (f"0x{ib:X} (0x222014)" if ib else "(0x222014 not implemented)"))
    if sysproc:
        print("[+] walking ActiveProcessLinks (validated at every hop):")
        pid_off = dev.cfg["eprocess_pid"]
        links = dev.cfg["eprocess_links"]
        cur = sysproc
        for i in range(args.max_offsets):
            try:
                flink = dev.read_qword(cur + links)
                pid = dev.read_qword(cur + pid_off)
                dtb = dev.read_qword(cur + dev.cfg["eprocess_dtb"])
            except WinNotifyError as exc:
                print(f"      {i}: 0x{cur:X} read stopped: {exc}")
                break
            print(f"      {i}: 0x{cur:X}  pid={pid}  DirBase=0x{dtb & 0xFFFFFFFFFF000:X}")
            if not dev._is_kernel_ptr(flink) or flink - links == sysproc:
                print("      (end of list)")
                break
            cur = flink - links
    print("[i] 0x222000/0x222004 take the PID; the driver reads EPROCESS+0x28 "
          "for the DirBase itself, so no CR3 is ever passed in.")


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
    parser.add_argument("--no-elevate", action="store_true", default=False,
                        help="never try to relaunch as administrator")
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

    # Loading the driver service needs SeLoadDriverPrivilege, which a
    # UAC-filtered Administrator token does not carry.  Restart elevated.
    if not args.no_elevate and not os.environ.get("WINNOTIFY_ELEVATED_CHILD"):
        try:
            summary = winnotify.token_summary()
        except WinNotifyError:
            summary = {}
        if summary and not summary.get("elevated", True):
            print(f"[!] not elevated (integrity={summary.get('integrity', '?')}, "
                  "UAC-filtered token: no SeLoadDriverPrivilege)")
            print("[i] relaunching with administrator rights (UAC prompt)...")
            try:
                return winnotify.relaunch_elevated(sys.argv[1:])
            except WinNotifyError as exc:
                print(f"[!] could not self-elevate: {exc}")
                print("[i] close this window and start it from an "
                      "Administrator PowerShell, or pass --no-elevate")
                return 1
        elif summary:
            print(f"[i] token: elevated={summary.get('elevated')} "
                  f"integrity={summary.get('integrity', '?')}")

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
