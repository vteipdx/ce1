unit StealthHiding;

{$mode objfpc}{$H+}

{ Process/Module/Thread hiding for CE Stealth Edition
  Uses kernel bridge physical memory access to unlink from kernel structures }

interface

uses
  windows, sysutils;

type
  TStealthHider = class
  private
    FHidden: Boolean;
    FPID: DWORD;
    FEPROCESS: QWORD;
    FPEB: QWORD;

    function FindOwnEPROCESS: QWORD;
    function GetPEBFromEPROCESS(EPROCESS: QWORD): QWORD;
  public
    constructor Create;
    destructor Destroy; override;

    function HideProcess: Boolean;
    function UnhideProcess: Boolean;
    function HideModules: Boolean;
    function UnhideModules: Boolean;
    function HideAll: Boolean;
    function UnhideAll: Boolean;

    property IsHidden: Boolean read FHidden;
  end;

var
  Stealth: TStealthHider;

implementation

uses
  KernelBridge, PhysicalMemory;

constructor TStealthHider.Create;
begin
  inherited;
  FHidden := False;
  FPID := GetCurrentProcessId;
  FEPROCESS := 0;
  FPEB := 0;
end;

destructor TStealthHider.Destroy;
begin
  if FHidden then UnhideAll;
  inherited;
end;

// EPROCESS offsets (Windows 10/11, x64 - approximate)
// These can vary by build. For academic purposes, using common offsets.
const
  // EPROCESS
  EPROCESS_UniqueProcessId    = $440;  // Win10 21H2+
  EPROCESS_ActiveProcessLinks = $448;  // LIST_ENTRY (FLINK, BLINK)
  EPROCESS_Peb                = $550;  // Pointer to PEB
  EPROCESS_ImageFileName      = $5A8;  // [15] char

  // PEB
  PEB_Ldr                      = $18;
  // PEB_LDR_DATA
  LDR_InLoadOrderModuleList    = $10;
  LDR_InMemoryOrderModuleList  = $20;
  LDR_InInitOrderModuleList    = $30;

  // LDR_DATA_TABLE_ENTRY
  LDR_BaseDllName              = $58;  // UNICODE_STRING
  LDR_DllBase                  = $30;
  LDR_SizeOfImage              = $40;
  LDR_InLoadOrderLinks         = $0;   // LIST_ENTRY (offset within LDR_DATA_TABLE_ENTRY)

function TStealthHider.FindOwnEPROCESS: QWORD;
var
  pid: DWORD;
  scanAddr: QWORD;
  i: Integer;
  physBase: QWORD;
begin
  Result := 0;
  if (KernelBr = nil) or (KernelBr.State <> kbsReady) then Exit;

  pid := FPID;

  // Walk PsActiveProcessLinks starting from System (PID 4)
  // This requires finding the list head first

  // Alternative: scan kernel memory for our PID near EPROCESS-like structures
  // EPROCESS has a recognizable DISPATCHER_HEADER at offset 0
  // Type=3 (Process object), Size is variable

  // ponytail: simplified scan - look for our PID at known EPROCESS offsets
  // The kernel heap where EPROCESS resides is typically in the 0xFFFFC00000000000 range
  // Physical addresses vary

  OutputDebugString('[Stealth] Searching for own EPROCESS...');

  // Use PsGetCurrentProcess equivalent: read gs:[188] -> ETHREAD -> EPROCESS
  // From user mode, we can't directly access gs segment
  // Instead, we search for our image name in kernel memory

  // Simplified: iterate ActiveProcessLinks by scanning physical mem
  // Full implementation needs signature-based EPROCESS locator
  
  OutputDebugString('[Stealth] EPROCESS search requires kernel symbol resolution - using fallback');
  Result := 0;
end;

function TStealthHider.GetPEBFromEPROCESS(EPROCESS: QWORD): QWORD;
var
  pebPhys: QWORD;
begin
  Result := 0;
  if not PhysMem.Initialized then Exit;

  // PEB is at EPROCESS + $550 (varies by build)
  pebPhys := PhysMem.VirtualToPhysical(EPROCESS + EPROCESS_Peb);
  if pebPhys = 0 then Exit;

  Result := PhysMem.ReadPhysicalQWORD(pebPhys);
end;

function TStealthHider.HideProcess: Boolean;
var
  flinkPhys, blinkPhys: QWORD;
  flink, blink: QWORD;
begin
  Result := False;
  if (KernelBr = nil) or (KernelBr.State <> kbsReady) then Exit;

  FEPROCESS := FindOwnEPROCESS;
  if FEPROCESS = 0 then Exit;

  // Unlink from PsActiveProcessLinks:
  // FLINK->BLINK = BLINK
  // BLINK->FLINK = FLINK
  flinkPhys := PhysMem.VirtualToPhysical(FEPROCESS + EPROCESS_ActiveProcessLinks);
  blinkPhys := flinkPhys + 8;

  flink := PhysMem.ReadPhysicalQWORD(flinkPhys);
  blink := PhysMem.ReadPhysicalQWORD(blinkPhys);

  if (flink <> 0) and (blink <> 0) then
  begin
    // Write FLINK.BLINK = BLINK (FLINK+0x8 = BLINK)
    PhysMem.WritePhysicalQWORD(
      PhysMem.VirtualToPhysical(flink),
      blink
    );
    // Write BLINK.FLINK = FLINK (BLINK+0x0 = FLINK)
    PhysMem.WritePhysicalQWORD(
      PhysMem.VirtualToPhysical(blink),
      flink
    );

    FHidden := True;
    Result := True;
    OutputDebugString('[Stealth] Process unlinked from ActiveProcessLinks');
  end;
end;

function TStealthHider.UnhideProcess: Boolean;
begin
  // Re-link would require saving original FLINK/BLINK values
  // For academic purposes, documented as a limitation
  Result := False;
end;

function TStealthHider.HideModules: Boolean;
var
  peb, ldr: QWORD;
  headEntry, currentEntry: QWORD;
  ourBase: QWORD;
  entryFlink, entryBlink: QWORD;
  flinkPhys, blinkPhys: QWORD;
  baseAddr: QWORD;
begin
  Result := False;
  if (KernelBr = nil) or (KernelBr.State <> kbsReady) then Exit;

  // Get our base address
  ourBase := QWORD(GetModuleHandle(nil));
  if ourBase = 0 then Exit;

  // Get PEB from our process
  FPEB := GetPEBFromEPROCESS(FEPROCESS);
  if FPEB = 0 then Exit;

  // Read PEB->Ldr
  ldr := KernelBr.ReadVirtualQWORD(FPID, FPEB + PEB_Ldr);

  // Walk InLoadOrderModuleList
  headEntry := ldr + LDR_InLoadOrderModuleList;
  // Manual walk via physical memory...
  
  // ponytail: full module hiding requires walking kernel structures.
  // For the academic demo, concept is documented.
  OutputDebugString('[Stealth] Module hiding: PEB-based unlinking (requires full kernel walk)');
  Result := False; // Demo only - full implementation needs per-build offsets
end;

function TStealthHider.UnhideModules: Boolean;
begin
  Result := False;
end;

function TStealthHider.HideAll: Boolean;
begin
  Result := HideProcess;
  // HideModules is optional and complex - skip for now
end;

function TStealthHider.UnhideAll: Boolean;
begin
  Result := UnhideProcess;
end;

initialization
  Stealth := TStealthHider.Create;

finalization
  Stealth.Free;

end.
