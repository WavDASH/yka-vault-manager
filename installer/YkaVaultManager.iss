#define AppVersion "1.0.2"
[Setup]
AppId={{D16CC63C-FA8D-4B3B-AC55-51C3764752D8}
AppName=YKA Vault Manager
AppVersion={#AppVersion}
AppPublisher=YKA Vault Manager Project
DefaultDirName={autopf}\YKA Vault Manager
DefaultGroupName=YKA Vault Manager
UninstallDisplayIcon={app}\YkaVaultManager.exe
SetupIconFile=..\assets\yka.ico
OutputDir=..\dist
OutputBaseFilename=YkaVaultManager-Setup-{#AppVersion}
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
PrivilegesRequired=admin
WizardStyle=modern
Compression=lzma2
SolidCompression=yes
LicenseFile=..\LICENSE
InfoBeforeFile=InstallerNotice.txt
AppMutex=Local\YKA.VaultManager.Running
CloseApplications=no
RestartApplications=no
Uninstallable=yes

[Tasks]
Name: desktopicon; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "..\dist\portable-{#AppVersion}\YkaVaultManager\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\vendor\installers\winfsp-2.1.25156.msi"; Flags: dontcopy

[Icons]
Name: "{group}\YKA Vault Manager"; Filename: "{app}\YkaVaultManager.exe"
Name: "{autodesktop}\YKA Vault Manager"; Filename: "{app}\YkaVaultManager.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\YkaVaultManager.exe"; Description: "Open YKA Vault Manager"; Flags: nowait postinstall skipifsilent runasoriginaluser

[Code]
function HasWinFsp: Boolean;
var InstallDir: String;
begin
  Result := (RegQueryStringValue(HKLM32, 'SOFTWARE\WinFsp', 'InstallDir', InstallDir)
    or RegQueryStringValue(HKLM64, 'SOFTWARE\WinFsp', 'InstallDir', InstallDir))
    and FileExists(AddBackslash(InstallDir) + 'bin\winfsp-x64.dll');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var Code: Integer; PackagePath: String;
begin
  Result := '';
  if HasWinFsp then exit;
  ExtractTemporaryFile('winfsp-2.1.25156.msi');
  PackagePath := ExpandConstant('{tmp}\winfsp-2.1.25156.msi');
  if GetSHA256OfFile(PackagePath) <> '073a70e00f77423e34bed98b86e600def93393ba5822204fac57a29324db9f7a' then begin
    Result := 'The WinFsp installer failed its integrity check. Download YKA Setup again.'; exit;
  end;
  if not Exec(ExpandConstant('{sys}\msiexec.exe'), '/i "' + PackagePath + '" /passive /norestart', '', SW_SHOW, ewWaitUntilTerminated, Code) then begin
    Result := 'WinFsp could not be installed. Install it separately, then run YKA Setup again.'; exit;
  end;
  if Code = 3010 then NeedsRestart := True
  else if (Code <> 0) or not HasWinFsp then
    Result := 'WinFsp installation did not complete. Resolve its installer error before continuing.';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var Command: String;
begin
  if CurUninstallStep = usPostUninstall then
    if RegQueryStringValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'YkaVaultManager', Command) then
      if Pos(ExpandConstant('{app}\YkaVaultManager.exe'), Command) > 0 then
        RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'YkaVaultManager');
  { Never delete per-user Registry, settings, icons, Keyrings or encrypted folders. }
  { WinFsp is shared with other applications and is not removed. }
end;
