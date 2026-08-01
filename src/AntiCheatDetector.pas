unit AntiCheatDetector;

{$mode objfpc}{$H+}

interface

uses
  windows, sysutils, classes, jwawindows;

type
  TAntiCheatType = (
    acNone,
    acWarden,       // Blizzard
    acVAC,          // Valve
    acEAC,          // Easy Anti-Cheat
    acBattlEye,     // BattlEye
    acXIGNCODE,     // XIGNCODE3
    acNProtect,     // nProtect GameGuard
    acRicochet,     // Call of Duty
    acVanguard,     // Riot Vanguard
    acFaceit,       // Faceit
    acESEA          // ESEA
  );

  TAntiCheatInfo = record
    AType: TAntiCheatType;
    Name: string;
    IsKernelLevel: Boolean;
    IsHypervisorLevel: Boolean;
  end;

const
  AntiCheatNames: array[TAntiCheatType] of string = (
    'None', 'Warden', 'VAC', 'EasyAntiCheat', 'BattlEye',
    'XIGNCODE3', 'nProtect GameGuard', 'Ricochet', 'Vanguard', 'Faceit', 'ESEA'
  );

  // Known anti-cheat driver service names
  ACEACServiceNames: array[0..1] of string = ('EasyAntiCheat', 'EasyAntiCheat_EOS');
  ACBEServiceNames: array[0..1] of string = ('BEDaisy', 'BattlEye Service');
  ACVanguardServiceNames: array[0..1] of string = ('vgk', 'vgc');
  ACXIGNServiceNames: array[0..1] of string = ('XIGNCode3', 'x3service');
  ACRicochetServiceNames: array[0..1] of string = ('ricochet', 'crashhandler');

  // Known anti-cheat driver filenames
  ACEACDrivers: array[0..2] of string = ('EasyAntiCheat.sys', 'EasyAntiCheat_EOS.sys', 'EasyAntiCheat');
  ACBEDrivers: array[0..2] of string = ('BEDaisy.sys', 'BEDaisy', 'be_driver.sys');
  ACVanguardDrivers: array[0..2] of string = ('vgk.sys', 'vgk', 'vgc.sys');
  ACXIGNDrivers: array[0..2] of string = ('x3.xem', 'xnl.sys', 'xhunter1.sys');
  ACRicochetDrivers: array[0..2] of string = ('randgrid.sys', 'shmvcb.sys');

  // Known anti-cheat process names
  ACEACProcesses: array[0..2] of string = ('EasyAntiCheat.exe', 'EasyAntiCheat_EOS.exe', 'eac_launcher.exe');
  ACBEProcesses: array[0..2] of string = ('BEService.exe', 'BEService_x64.exe', 'be_client.exe');
  ACVanguardProcesses: array[0..2] of string = ('vgc.exe', 'vgtray.exe', 'vgk.exe');
  ACXIGNProcesses: array[0..2] of string = ('x3.xem', 'XIGNCode3', 'xcoronahost.xem');
  ACRicochetProcesses: array[0..2] of string = ('cod.exe', 'ricochet_service.exe');
  ACFaceitProcesses: array[0..2] of string = ('faceit.exe', 'faceitclient.exe', 'faceit_acs.exe');
  ACESEAProcesses: array[0..2] of string = ('eseaclient.exe', 'eslwire.exe');

function DetectAntiCheat: TAntiCheatInfo;
function IsKernelAntiCheatActive: Boolean;
function GetAntiCheatName(AType: TAntiCheatType): string;
function ShouldUseKernelBridge(AC: TAntiCheatType): Boolean;

implementation

uses
  registry;

function GetServiceStatus(ServiceName: string): DWORD;
var
  hSCM, hService: THandle;
  status: TServiceStatus;
begin
  Result := 0;
  hSCM := OpenSCManager(nil, nil, SC_MANAGER_ENUMERATE_SERVICE);
  if hSCM = 0 then Exit;

  hService := OpenService(hSCM, PChar(ServiceName), SERVICE_QUERY_STATUS);
  if hService <> 0 then
  begin
    if QueryServiceStatus(hService, status) then
      Result := status.dwCurrentState;
    CloseServiceHandle(hService);
  end;

  CloseServiceHandle(hSCM);
end;

function IsDriverLoaded(DriverName: string): Boolean;
var
  hDevice: THandle;
begin
  hDevice := CreateFile(PChar('\\.\' + DriverName),
    GENERIC_READ or GENERIC_WRITE,
    FILE_SHARE_READ or FILE_SHARE_WRITE,
    nil, OPEN_EXISTING, 0, 0);
  Result := (hDevice <> INVALID_HANDLE_VALUE);
  if Result then CloseHandle(hDevice);

  // Also check as a filter driver
  if not Result then
  begin
    hDevice := CreateFile(PChar('\\.\' + ChangeFileExt(DriverName, '')),
      GENERIC_READ, FILE_SHARE_READ, nil, OPEN_EXISTING, 0, 0);
    Result := (hDevice <> INVALID_HANDLE_VALUE);
    if Result then CloseHandle(hDevice);
  end;
end;

function IsProcessRunning(ProcName: string): Boolean;
var
  hSnapshot: THandle;
  pe: TProcessEntry32;
begin
  Result := False;
  hSnapshot := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if hSnapshot = INVALID_HANDLE_VALUE then Exit;

  pe.dwSize := SizeOf(pe);
  if Process32First(hSnapshot, pe) then
  begin
    repeat
      if SameText(pe.szExeFile, ProcName) then
      begin
        Result := True;
        Break;
      end;
    until not Process32Next(hSnapshot, pe);
  end;

  CloseHandle(hSnapshot);
end;

function DetectAntiCheat: TAntiCheatInfo;
var
  i: Integer;
  svcState: DWORD;
begin
  FillChar(Result, SizeOf(Result), 0);
  Result.AType := acNone;
  Result.Name := 'None';

  // Check hypervisor-level ACs first (most dangerous)

  // Vanguard (hypervisor, boot-time)
  svcState := GetServiceStatus('vgk');
  if svcState = SERVICE_RUNNING then
  begin
    Result.AType := acVanguard;
    Result.Name := AntiCheatNames[acVanguard];
    Result.IsKernelLevel := True;
    Result.IsHypervisorLevel := True;
    Exit;
  end;

  // Check kernel-level ACs

  // BattlEye
  for i := 0 to High(ACBEDrivers) do
  begin
    if IsDriverLoaded(ACBEDrivers[i]) then
    begin
      Result.AType := acBattlEye;
      Result.Name := AntiCheatNames[acBattlEye];
      Result.IsKernelLevel := True;
      Exit;
    end;
  end;

  // EAC
  for i := 0 to High(ACEACDrivers) do
  begin
    if IsDriverLoaded(ACEACDrivers[i]) then
    begin
      Result.AType := acEAC;
      Result.Name := AntiCheatNames[acEAC];
      Result.IsKernelLevel := True;
      Exit;
    end;
  end;

  // Ricochet
  for i := 0 to High(ACRicochetDrivers) do
  begin
    if IsDriverLoaded(ACRicochetDrivers[i]) then
    begin
      Result.AType := acRicochet;
      Result.Name := AntiCheatNames[acRicochet];
      Result.IsKernelLevel := True;
      Exit;
    end;
  end;

  // Faceit/ESEA
  for i := 0 to High(ACFaceitProcesses) do
    if IsProcessRunning(ACFaceitProcesses[i]) then
    begin
      Result.AType := acFaceit;
      Result.Name := AntiCheatNames[acFaceit];
      Result.IsKernelLevel := True;
      Exit;
    end;

  for i := 0 to High(ACESEAProcesses) do
    if IsProcessRunning(ACESEAProcesses[i]) then
    begin
      Result.AType := acESEA;
      Result.Name := AntiCheatNames[acESEA];
      Result.IsKernelLevel := True;
      Exit;
    end;

  // Check user-mode/low ACs

  // XIGNCODE
  for i := 0 to High(ACXIGNProcesses) do
    if IsProcessRunning(ACXIGNProcesses[i]) then
    begin
      Result.AType := acXIGNCODE;
      Result.Name := AntiCheatNames[acXIGNCODE];
      Exit;
    end;

  for i := 0 to High(ACXIGNDrivers) do
    if IsDriverLoaded(ACXIGNDrivers[i]) then
    begin
      Result.AType := acXIGNCODE;
      Result.Name := AntiCheatNames[acXIGNCODE];
      Exit;
    end;

  // nProtect
  svcState := GetServiceStatus('npggsvc');
  if svcState = SERVICE_RUNNING then
  begin
    Result.AType := acNProtect;
    Result.Name := AntiCheatNames[acNProtect];
    Exit;
  end;

  // EAC process check (some versions are user-mode only)
  for i := 0 to High(ACEACProcesses) do
    if IsProcessRunning(ACEACProcesses[i]) then
    begin
      Result.AType := acEAC;
      Result.Name := AntiCheatNames[acEAC];
      Exit;
    end;

  // BE process check
  for i := 0 to High(ACBEProcesses) do
    if IsProcessRunning(ACBEProcesses[i]) then
    begin
      Result.AType := acBattlEye;
      Result.Name := AntiCheatNames[acBattlEye];
      Exit;
    end;

  // Warden: check for Blizzard agent
  if IsProcessRunning('BlizzardBrowser.exe') or
     IsProcessRunning('Agent.exe') or
     IsProcessRunning('Battle.net.exe') or
     IsProcessRunning('Hearthstone.exe') or
     IsProcessRunning('Wow.exe') or
     IsProcessRunning('WowClassic.exe') or
     IsProcessRunning('Diablo IV.exe') or
     IsProcessRunning('Overwatch.exe') then
  begin
    Result.AType := acWarden;
    Result.Name := AntiCheatNames[acWarden];
    Exit;
  end;

  // VAC: check for Steam client
  if IsProcessRunning('Steam.exe') or
     IsProcessRunning('steamclient.dll') or
     IsProcessRunning('steamservice.exe') then
  begin
    // VAC modules are loaded per-game, not as a separate process
    // Detecting Steam means VAC-capable, not necessarily active
    Result.AType := acNone; // Don't auto-detect VAC, it's not aggressive
  end;

  Result.AType := acNone;
  Result.Name := 'None';
end;

function IsKernelAntiCheatActive: Boolean;
var
  ac: TAntiCheatInfo;
begin
  ac := DetectAntiCheat;
  Result := ac.IsKernelLevel;
end;

function GetAntiCheatName(AType: TAntiCheatType): string;
begin
  Result := AntiCheatNames[AType];
end;

function ShouldUseKernelBridge(AC: TAntiCheatType): Boolean;
begin
  // Use kernel bridge for all kernel-level anti-cheats
  case AC of
    acEAC, acBattlEye, acRicochet, acNProtect, acFaceit, acESEA:
      Result := True;
    acVanguard:
      Result := True; // We try, but hypervisor AC is extremely difficult
    else
      Result := False; // Warden, VAC, XIGNCODE, none → user-mode syscalls sufficient
  end;
end;

end.
