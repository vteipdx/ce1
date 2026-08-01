# Cheat Engine Undetectable

**Academic Research Edition** — Modified Cheat Engine with multi-tiered anti-cheat evasion for cybersecurity education and university-level reverse engineering research.

> **Disclaimer:** This project is exclusively for academic research, university coursework, and cybersecurity education. It must be destroyed upon completion of the academic term. Usage against live game services without explicit permission violates terms of service.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Cheat Engine 7.5                      │
│                   (Lazarus / FreePascal)                  │
├─────────────────────────────────────────────────────────┤
│  T1: Surface Obfuscation                                 │
│  ├─ Window/process/registry name randomization (-daltname)│
│  ├─ PE metadata stripping & section renaming              │
│  └─ Rich Header removal & timestamp randomization         │
├─────────────────────────────────────────────────────────┤
│  T2: Syscall Gateway                                     │
│  ├─ Direct syscall stubs (x64)                           │
│  ├─ Dynamic syscall number extraction from disk          │
│  └─ Bypasses user-mode ntdll hooks (EAC/BE)             │
├─────────────────────────────────────────────────────────┤
│  T3: Kernel Bridge (BYOVD)                               │
│  ├─ Anti-cheat detection (10 engines)                    │
│  ├─ Vulnerable driver loader (RTCore64.sys)              │
│  ├─ Physical memory R/W via IOCTL                        │
│  ├─ Virtual-to-physical page table walking               │
│  ├─ ObCallback bypass (disables handle stripping)        │
│  └─ Process hiding (PsActiveProcessLinks unlinking)      │
└─────────────────────────────────────────────────────────┘
```

## Coverage Matrix

| Anti-Cheat | Type | Strategy | Status |
|-----------|------|----------|--------|
| Warden (Blizzard) | User-mode | T1 + T2 syscall bypass | Functional |
| VAC (Valve) | User-mode | T1 + T2 syscall bypass | Functional |
| XIGNCODE3 | User-mode driver | T1 + T2 syscall bypass | Functional |
| EasyAntiCheat | Kernel driver | T3 kernel bridge | Requires RTCore64.sys |
| BattlEye | Kernel driver | T3 kernel bridge | Requires RTCore64.sys |
| nProtect GameGuard | Kernel driver | T3 kernel bridge | Requires RTCore64.sys |
| Ricochet (CoD) | Kernel driver | T3 kernel bridge | Partial |
| Vanguard (Riot) | Hypervisor | N/A | Out of scope |
| Faceit / ESEA | Kernel + Hypervisor | N/A | Out of scope |

## File Structure

```
Cheat Engine/
├── Source Modifications (T1-T3)
│   ├── cheatengine.lpi          # Project: renamed metadata, -daltname define
│   ├── cheatengine.lpr          # Main: dynamic Application.Title
│   └── NewKernelHandler.pas     # Core: Syscall + Kernel bridge integration
│
├── New Units
│   ├── SyscallGateway.pas       # Direct syscall stubs (Read/Write/Open/VQE)
│   ├── AntiCheatDetector.pas    # AC detection: processes, drivers, services
│   ├── PhysicalMemory.pas       # Driver loader + physical memory R/W
│   ├── KernelBridge.pas         # Kernel bypass orchestrator
│   └── StealthHiding.pas        # Process/module hiding via PEB unlinking
│
├── Build Tools
│   ├── Build.ps1               # Automated build pipeline (root)
│
└── cheat-engine/                # Upstream CE source (git submodule or clone)
```

## How It Works

### Tier 1: Surface Obfuscation

Uses CE's built-in `{$ifdef altname}` conditional compilation. When compiled with `-daltname`:

- Window title: `"Runtime Modifier"` instead of `"Cheat Engine 7.5"`
- Registry keys: `\Software\Runtime Modifier\` instead of `\Software\Cheat Engine\`
- All user-facing strings: "Modification", "Code Table", etc.
- PE metadata: generic company/file descriptions
- Output name: `sysdiag64.exe` instead of `cheatengine-x86_64.exe`

### Tier 2: Syscall Gateway

CE's DBK kernel driver is disabled (its certificate hash is blacklisted by EAC/BE). Instead, all memory access functions (`ReadProcessMemory`, `WriteProcessMemory`, `VirtualQueryEx`, `OpenProcess`) are redirected through direct `syscall` instruction stubs.

- Reads `ntdll.dll` from disk before any anti-cheat hooks are active
- Parses PE export table to extract raw syscall numbers
- Generates assembly stubs: `mov r10, rcx; mov eax, [syscall_num]; syscall; ret`
- Bypasses user-mode hooks in `ntdll.dll` installed by EAC/BE

### Tier 3: Kernel Bridge (BYOVD)

For kernel-level anti-cheats that block handle creation via `ObRegisterCallbacks`:

1. **Detection**: Scans for EAC/BE drivers (`EasyAntiCheat.sys`, `BEDaisy.sys`) and services
2. **Driver loading**: Loads `RTCore64.sys` (MSI Afterburner, signed, CVE-2019-16098) via Windows Service Control Manager
3. **Physical memory mapping**: Uses IOCTL `0x80002000` to map arbitrary physical memory into user space
4. **Page table walking**: Translates target process virtual addresses → physical via 4-level paging
5. **Direct R/W**: Reads/writes target process memory through physical addresses, bypassing ALL handle checks
6. **ObCallback bypass**: Locates and disables EAC/BE pre-operation callbacks in the kernel's callback list
7. **Process hiding**: Unlinks CE's EPROCESS from `PsActiveProcessLinks`

## Prerequisites

1. **Lazarus IDE** 3.x with FreePascal 3.2.2: https://www.lazarus-ide.org/
2. **Git** for cloning the upstream CE repository
3. **Administrator privileges** (required for driver loading and process access)
4. **RTCore64.sys** — Obtain from an MSI Afterburner installation:
   - Path: `C:\Program Files (x86)\MSI Afterburner\RTCore64.sys`
   - Copy to: `C:\Windows\System32\drivers\RTCore64.sys`
   - Or place alongside the compiled executable

## Build Instructions

```powershell
```
git clone https://github.com/NulledNah/cheat-engine-undetectable.git
cd cheat-engine-undetectable
.\Build.ps1 -Clean

# If Lazarus is not in C:\lazarus:
.\Build.ps1 -Clean -LazarusPath "D:\lazarus"
```
```

The script:
1. Randomizes build identifiers (version, build number)
2. Compiles with `lazbuild` in Release 64-Bit mode
3. Runs PEPatcher to strip Rich Header, rename sections, randomize timestamp
4. Outputs `bin\sysdiag64.exe`

## Runtime Behavior

```
Launch sysdiag64.exe
  │
  ├─ DetectAntiCheat() → scans for running AC engines
  │
  ├─ [No kernel AC detected]
  │   └─ T1+T2 active: syscall bypass for all operations
  │
  ├─ [EAC/BE detected + RTCore64.sys available]
  │   ├─ Load driver via SCM
  │   ├─ Map physical memory
  │   ├─ Locate ntoskrnl base
  │   ├─ Disable ObCallbacks (if possible)
  │   ├─ Hide own process from enumeration
  │   └─ All memory ops via physmem R/W (zero handles needed)
  │
  └─ [Vanguard/Faceit detected]
      └─ Warning: hypervisor AC — limited functionality
```

## Academic Context

This project demonstrates the following cybersecurity concepts:

- **CVE Exploitation**: CVE-2019-16098 — signed driver vulnerability allowing arbitrary physical memory mapping from unprivileged user mode
- **Kernel Object Manipulation**: Direct modification of `EPROCESS`, `ObCallbacks`, and page table structures
- **PE File Format**: Programmatic manipulation of Rich Header, section headers, debug directories
- **Anti-Cheat Architecture**: Understanding the detection stack: user-mode hooks → kernel callbacks → hypervisor protection
- **Windows Internals**: x64 paging (PML4→PDP→PD→PT), syscall mechanism, Object Manager, Service Control Manager
- **Evasion Techniques**: Surface obfuscation, syscall gateway, handle cloaking, process hiding

## Limitations

- **Vanguard** operates at the hypervisor level (boot-time driver) and cannot be bypassed without a custom hypervisor or hardware DMA device
- **Faceit/ESEA** use layered kernel + hypervisor protection
- **RTCore64.sys** may be blacklisted by future anti-cheat updates; the cat-and-mouse game is inherent to this research area
- Windows 11 with HVCI/VBS active may prevent loading vulnerable drivers

## References

- CVE-2019-16098: RTCore64.sys arbitrary physical memory read/write
- Cheat Engine: https://github.com/cheat-engine/cheat-engine
- Windows NT Kernel: ObRegisterCallbacks, PsActiveProcessLinks, x64 Page Tables
- Lazarus IDE: https://www.lazarus-ide.org/

---

**Academic Use Only** — This project is part of a university thesis/research curriculum. It will be destroyed upon completion of the academic term per university policy.
