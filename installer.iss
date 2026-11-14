; XOS Toolkit Installer (Rust build) - Inno Setup Script
; Same AppId, install folder and CPU service task as the earlier C# Toolkit installer, so an existing install upgrades in place.

#define MyAppName "XOS Toolkit"
#define MyAppVersion "0.3.2"
#define MyAppPublisher "imribiy"
#define MyAppExeName "XOS-Toolkit.exe"
#define MyAppURL "https://github.com/imribiy/xos"
#define SharedResources "resources"

[Setup]
AppId={{3169-XOS-TOOLKIT-3169}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=target\installer
OutputBaseFilename=XOS-Toolkit-Setup
SetupIconFile=crates\xos-toolkit\assets\XOS.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
DisableWelcomePage=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startmenuicon"; Description: "Create a Start Menu shortcut"; GroupDescription: "{cm:AdditionalIcons}"

[InstallDelete]
; The C# build shipped .NET config files beside both executables; the Rust build has none.
Type: files; Name: "{app}\XOS-Toolkit.exe.config"
Type: files; Name: "{app}\XOS-CpuService.exe.config"

[Files]
Source: "target\release\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "target\release\XOS-CpuService.exe"; DestDir: "{app}"; Flags: ignoreversion
; Chocolatey installer - dropped next to the toolkit so we can (re)install it any time
Source: "{#SharedResources}\chocolatey-2.7.1.0.msi"; DestDir: "{app}\Bundled"; Flags: ignoreversion
; Open-Shell Fluent Metro skin files are the offline source. The toolkit downloads the
; release only if either bundled file is missing from the Open-Shell Skins folder.
Source: "{#SharedResources}\Fluent-Metro.skin";  DestDir: "{commonpf}\Open-Shell\Skins"; Flags: ignoreversion uninsneveruninstall
Source: "{#SharedResources}\Fluent-Metro.skin7"; DestDir: "{commonpf}\Open-Shell\Skins"; Flags: ignoreversion uninsneveruninstall

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: startmenuicon
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"; Tasks: startmenuicon

[Code]
const
  TesterUninstallKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{8B4F1A2C-3169-4D5E-9F0A-316931693169}_is1';

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  UninstallCommand: String;
  ResultCode: Integer;
begin
  Result := '';
  if not RegQueryStringValue(HKLM64, TesterUninstallKey, 'QuietUninstallString', UninstallCommand) then
    RegQueryStringValue(HKLM64, TesterUninstallKey, 'UninstallString', UninstallCommand);

  if UninstallCommand <> '' then
  begin
    UninstallCommand := UninstallCommand + ' /VERYSILENT /SUPPRESSMSGBOXES /NORESTART';
    if not Exec('>', UninstallCommand, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
      Result := 'The previous XOS Toolkit tester build could not be removed. Close the Toolkit and try again.'
    else if ResultCode <> 0 then
      Result := 'The previous XOS Toolkit tester build returned an error while being removed. Restart Windows and try again.';
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssInstall then
  begin
    Exec('taskkill.exe', '/f /im XOS-Toolkit.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('taskkill.exe', '/f /im XOS-CpuService.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end
  else if CurStep = ssPostInstall then
  begin
    { Resume an existing affinity task after replacing its executable. }
    Exec('schtasks.exe', '/run /tn "XOS CPU Service"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    Exec('taskkill.exe', '/f /im XOS-Toolkit.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('taskkill.exe', '/f /im XOS-CpuService.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('schtasks.exe', '/delete /tn "XOS CPU Service" /f', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent runascurrentuser


[UninstallDelete]
Type: dirifempty; Name: "{app}\Bundled"
Type: dirifempty; Name: "{app}"
