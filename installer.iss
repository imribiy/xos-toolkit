; XOS Toolkit Installer (Rust build) - Inno Setup Script
; Same AppId, install folder and CPU service task as the earlier C# Toolkit installer, so an existing install upgrades in place.

#define MyAppName "XOS Toolkit"
#define MyAppVersion "0.6.1"
#define MyAppPublisher "imribiy"
#define MyAppExeName "XOS-Toolkit.exe"
#define MyAppURL "https://github.com/imribiy/xos"
#define SharedResources "resources"
#define XSudoExe "resources\XSudo.exe"

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
CloseApplicationsFilterExcludes=XSudo.exe
RestartApplications=no

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
Source: "{#XSudoExe}"; DestDir: "{commonpf64}\XSudo"; Flags: ignoreversion restartreplace uninsrestartdelete
; Chocolatey installer - dropped next to the toolkit so we can (re)install it any time
Source: "{#SharedResources}\chocolatey-2.7.1.0.msi"; DestDir: "{app}\Bundled"; Flags: ignoreversion
; XOS skin for Open-Shell (built by Source\OpenShellSkin\build.py); the toolkit also embeds it.
Source: "{#SharedResources}\XOS.skin7"; DestDir: "{commonpf}\Open-Shell\Skins"; Flags: ignoreversion uninsneveruninstall

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: startmenuicon
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"; Tasks: startmenuicon
Name: "{commonprograms}\XSudo"; Filename: "{commonpf64}\XSudo\XSudo.exe"; WorkingDir: "{commonpf64}\XSudo"; IconFilename: "{commonpf64}\XSudo\XSudo.exe"; IconIndex: 0; Comment: "Run programs as TrustedInstaller"; Flags: runminimized

[Code]
const
  TesterUninstallKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{8B4F1A2C-3169-4D5E-9F0A-316931693169}_is1';

function RelaunchRequested: Boolean;
begin
  Result := ExpandConstant('{param:RELAUNCH|0}') = '1';
end;

procedure DeleteNowOrAtRestart(const Path: String);
begin
  if FileExists(Path) and not DeleteFile(Path) then
    RestartReplace(Path, '');
end;

procedure TakeOverXSudo;
var
  Exe: String;
begin
  Exe := ExpandConstant('{commonpf64}\XSudo\XSudo.exe');
  DeleteNowOrAtRestart(Exe + '.old');
  if FileExists(Exe) and not DeleteFile(Exe) then
    if RenameFile(Exe, Exe + '.old') then
      RestartReplace(Exe + '.old', '');
end;

procedure RemoveXSudoVerb(const ClassName: String);
var
  ClassKey, Created: String;
begin
  ClassKey := 'SOFTWARE\Classes\' + ClassName;
  if not RegQueryStringValue(HKLM64, ClassKey + '\shell\XSudoRunAsTI', 'XSudoCreated', Created) then
    Created := '';
  RegDeleteKeyIncludingSubkeys(HKLM64, ClassKey + '\shell\XSudoRunAsTI');
  if (CompareText(Created, 'shell') = 0) or (CompareText(Created, 'class') = 0) then
    RegDeleteKeyIfEmpty(HKLM64, ClassKey + '\shell');
  if CompareText(Created, 'class') = 0 then
    RegDeleteKeyIfEmpty(HKLM64, ClassKey);
end;

procedure RemoveXSudoLeftovers;
var
  Dir: String;
begin
  RemoveXSudoVerb('exefile');
  RemoveXSudoVerb('batfile');
  RemoveXSudoVerb('cmdfile');
  RemoveXSudoVerb('Microsoft.PowerShellScript.1');
  RemoveXSudoVerb('mscfile');
  RemoveXSudoVerb('regfile');
  RemoveXSudoVerb('Folder');
  Dir := ExpandConstant('{commonpf64}\XSudo');
  DeleteNowOrAtRestart(Dir + '\XSudo.exe.old');
  if DirExists(Dir) and not RemoveDir(Dir) then
    RestartReplace(Dir, '');
end;

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
    TakeOverXSudo;
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
  end
  else if CurUninstallStep = usPostUninstall then
    RemoveXSudoLeftovers;
end;

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent runascurrentuser
Filename: "{app}\{#MyAppExeName}"; Flags: nowait runascurrentuser; Check: RelaunchRequested


[UninstallDelete]
Type: filesandordirs; Name: "{app}\Update"
Type: dirifempty; Name: "{app}\Bundled"
Type: dirifempty; Name: "{app}"
