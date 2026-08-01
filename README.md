# Cheat Engine Undetectable

**Academic Research Edition** — Modified Cheat Engine with multi-tiered anti-cheat evasion for cybersecurity education and university-level reverse engineering research.

> **Disclaimer:** This project is exclusively for academic research, university coursework, and cybersecurity education. It must be destroyed upon completion of the academic term.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Cheat Engine 7.5                      │
│                   (Lazarus / FreePascal)                  │
├─────────────────────────────────────────────────────────┤
│  T1: User-Mode Evasion                                   │
│  ├─ Window/process/registry name randomization (-daltname)│
│  ├─ PE metadata stripping & section renaming              │
│  ├─ Rich Header removal & timestamp randomization         │
│  ├─ Direct syscall stubs (bypass ntdll.dll hooks)         │
│  └─ Dynamic syscall number extraction from disk           │
├─────────────────────────────────────────────────────────┤
│  T2: Kernel Bridge (BYOVD)                                │
│  ├─ Anti-cheat detection (10 engines)                     │
│  ├─ Vulnerable driver loader (RTCore64.sys)               │
│  ├─ Physical memory R/W via IOCTL                         │
│  ├─ Virtual-to-physical page table walking                │
│  ├─ ObCallback bypass (disables handle stripping)         │
│  └─ Process hiding (PsActiveProcessLinks unlinking)       │
├─────────────────────────────────────────────────────────┤
│  T3: DMA Hardware [NOT IMPLEMENTED]                       │
│  └─ PCIe FPGA/device for hypervisor-level AC bypass       │
└─────────────────────────────────────────────────────────┘
```

## Coverage Matrix

| Anti-Cheat | Type | Strategy | Status |
|-----------|------|----------|--------|
| Warden (Blizzard) | User-mode | T1 | Functional |
| VAC (Valve) | User-mode | T1 | Functional |
| XIGNCODE3 | User-mode driver | T1 | Functional |
| EasyAntiCheat | Kernel driver | T2 | Requires RTCore64.sys |
| BattlEye | Kernel driver | T2 | Requires RTCore64.sys |
| nProtect GameGuard | Kernel driver | T2 | Requires RTCore64.sys |
| Ricochet (CoD) | Kernel driver | T2 | Partial |
| Vanguard (Riot) | Hypervisor | T3 (DMA) | NOT IMPLEMENTED |
| Faceit / ESEA | Kernel + Hypervisor | T3 (DMA) | NOT IMPLEMENTED |

## File Structure

```
.
├── README.md
├── Build.ps1                     # Automated build pipeline (clones CE, applies patches, builds)
├── .gitignore
├── src/
│   ├── cheatengine.lpi           # Project: renamed metadata, -daltname define, output renamed
│   ├── cheatengine.lpr           # Main: dynamic Application.Title
│   ├── NewKernelHandler.pas      # Core: T1+T2 integration, function pointer swap
│   ├── SyscallGateway.pas        # T1: Direct syscall stubs (Read/Write/Open/VQE)
│   ├── AntiCheatDetector.pas     # T2: AC detection — processes, drivers, services
│   ├── PhysicalMemory.pas        # T2: Driver loader + physical memory R/W via IOCTL
│   ├── KernelBridge.pas          # T2: Kernel bypass orchestrator + ObCallback disable
│   ├── StealthHiding.pas         # T2: Process hiding via PsActiveProcessLinks unlinking
│   ├── PEPatcher.ps1             # Post-build PE mutation
│   └── Build-Stealth.ps1         # Legacy standalone build script
└── cheat-engine/                  # Upstream CE source (cloned by Build.ps1)
```

## How It Works

### Tier 1: User-Mode Evasion

**Surface Obfuscation** — Uses CE's built-in `{$ifdef altname}` conditional compilation:

- Window title: `"Runtime Modifier"` instead of `"Cheat Engine 7.5"`
- Registry keys: `\Software\Runtime Modifier\` instead of `\Software\Cheat Engine\`
- All user-facing strings: "Modification", "Code Table", etc.
- PE metadata: generic company/file descriptions, stripped version info
- Output name: `sysdiag64.exe` instead of `cheatengine-x86_64.exe`

**Syscall Gateway** — CE's DBK kernel driver is disabled (its certificate hash is blacklisted by EAC/BE). Instead, all memory access functions (`ReadProcessMemory`, `WriteProcessMemory`, `VirtualQueryEx`, `OpenProcess`) are redirected through direct `syscall` instruction stubs:

- Reads `ntdll.dll` from disk before any anti-cheat hooks are active
- Parses PE export table to extract raw syscall numbers
- Generates assembly stubs: `mov r10, rcx; mov eax, [syscall_num]; syscall; ret`
- Bypasses user-mode hooks in `ntdll.dll` installed by EAC/BE

### Tier 2: Kernel Bridge (BYOVD)

For kernel-level anti-cheats that block handle creation via `ObRegisterCallbacks`:

1. **Detection**: Scans for EAC/BE drivers (`EasyAntiCheat.sys`, `BEDaisy.sys`) and services
2. **Driver loading**: Loads `RTCore64.sys` (MSI Afterburner, signed, CVE-2019-16098) via Windows Service Control Manager
3. **Physical memory mapping**: Uses IOCTL `0x80002000` to map arbitrary physical memory into user space
4. **Page table walking**: Translates target process virtual addresses → physical via 4-level paging
5. **Direct R/W**: Reads/writes target process memory through physical addresses, bypassing ALL handle checks
6. **ObCallback bypass**: Locates and disables EAC/BE pre-operation callbacks in the kernel's callback list
7. **Process hiding**: Unlinks CE's EPROCESS from `PsActiveProcessLinks`

### Tier 3: DMA Hardware (NOT IMPLEMENTED)

For hypervisor-level anti-cheats (Vanguard, Faceit), a PCIe DMA device would be needed to read physical RAM from the bus, bypassing both kernel and hypervisor protections. Documented as future research extension.

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
git clone https://github.com/NulledNah/cheat-engine-undetectable.git
cd cheat-engine-undetectable
.\Build.ps1 -Clean

# If Lazarus is not in C:\lazarus:
.\Build.ps1 -Clean -LazarusPath "D:\lazarus"
```

The script:
1. Clones upstream Cheat Engine (if not present)
2. Copies patched files into the upstream source
3. Randomizes build identifiers (version, build number)
4. Compiles with `lazbuild` in Release 64-Bit mode
5. Runs PEPatcher to strip Rich Header, rename sections, randomize timestamp
6. Outputs `bin\sysdiag64.exe`

## Runtime Behavior

```
Launch sysdiag64.exe
  │
  ├─ DetectAntiCheat() → scans for running AC engines
  │
  ├─ [No kernel AC detected]
  │   └─ T1 active: syscall bypass for all operations
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
      └─ Warning: hypervisor AC — requires T3 (DMA hardware, not implemented)
```

## Academic Context

This project demonstrates the following cybersecurity concepts:

- **CVE Exploitation**: CVE-2019-16098 — signed driver vulnerability allowing arbitrary physical memory mapping from unprivileged user mode
- **Kernel Object Manipulation**: Direct modification of `EPROCESS`, `ObCallbacks`, and page table structures
- **PE File Format**: Programmatic manipulation of Rich Header, section headers, debug directories
- **Anti-Cheat Architecture**: Understanding the detection stack: user-mode hooks → kernel callbacks → hypervisor protection
- **Windows Internals**: x64 paging (PML4→PDP→PD→PT), syscall mechanism, Object Manager, Service Control Manager
- **Evasion Techniques**: Surface obfuscation, syscall gateway, handle cloaking, process hiding, BYOVD

## Limitations

- **Vanguard** operates at the hypervisor level (boot-time driver) and cannot be bypassed without T3 (DMA hardware)
- **Faceit/ESEA** use layered kernel + hypervisor protection — requires T3
- **RTCore64.sys** may be blacklisted by future anti-cheat updates; the cat-and-mouse dynamic is inherent to this research area
- Windows 11 with HVCI/VBS active may prevent loading vulnerable drivers

## References

- CVE-2019-16098: RTCore64.sys arbitrary physical memory read/write
- Cheat Engine: https://github.com/cheat-engine/cheat-engine
- Windows NT Kernel: ObRegisterCallbacks, PsActiveProcessLinks, x64 Page Tables
- Lazarus IDE: https://www.lazarus-ide.org/

---

**Academic Use Only** — This project is part of a university thesis/research curriculum. It will be destroyed upon completion of the academic term per university policy.
