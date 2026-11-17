# XSudo

XSudo runs a command in the caller's own console with an elevated identity. It
is a clean-room Rust reimplementation of the MinSudo command line, built for the
XOS project, and is drop-in compatible with the option names, aliases, prefixes
and value separators that existing XOS call sites use.

By default the command runs as Administrator. It can instead run as
NT AUTHORITY\SYSTEM or NT SERVICE\TrustedInstaller, and can enable every
privilege already present in the chosen token. The child shares the caller's
console and standard handles, so pipes and redirection work, and XSudo waits for
the child and returns its real exit code.

## Usage

```
XSudo [options] [program] [arguments...]
XSudo --Launch FILE
XSudo --Import FILE
XSudo --OpenFolder FOLDER
XSudo --ContextMenu=On|Off
XSudo
```

With options but no program, cmd.exe is started. With no arguments at all,
XSudo opens its window (below). Options are case insensitive. The prefixes
`-`, `--` and `/` are interchangeable. A value for `--WorkDir` is attached with
`=` or `:`; a space does not separate a value. Options after the program name
are passed to the child unchanged.

## Options

| Option | Aliases | Meaning |
| --- | --- | --- |
| `--Help` | `-H`, `/?` | Show help and exit 0. |
| `--Version` | `-Ver` | Show version and exit 0. |
| `--NoLogo` | `-NoL` | Do not print the startup banner. |
| `--Verbose` | `-V` | Print extra information to stdout. |
| `--System` | `-S` | Run as NT AUTHORITY\SYSTEM. |
| `--TrustedInstaller` | `-TI` | Run as NT SERVICE\TrustedInstaller. |
| `--Privileged` | `-P` | Enable every privilege present in the token. |
| `--WorkDir=PATH` | `-WD=PATH` | Set the child working directory. |
| `--Launch FILE` | | Run FILE as TrustedInstaller in its own window and return at once (see below). |
| `--Import FILE` | | Import a `.reg` file as TrustedInstaller and show the result (see below). |
| `--OpenFolder FOLDER` | | Open FOLDER in an Explorer window that runs as TrustedInstaller (see below). |
| `--ContextMenu=On` | `--ContextMenu=Off` | Add or remove the Explorer right-click entries (see below). |

## Exit codes

When the child is started and exits, XSudo returns the child's real exit code.
XSudo's own failures use reserved codes that no ordinary program returns:

| Code | Meaning |
| --- | --- |
| `0x58530001` | Usage error (bad or unrecognized command line). |
| `0x58530002` | Elevation could not be obtained or was declined. |
| `0x58530003` | The requested identity token could not be obtained. |
| `0x58530004` | The child process could not be started. |
| `0x58530005` | The working directory is invalid. |

Help and version exit 0.

## Identity per mode

- Administrator: the caller's own elevated token.
- System: the token of the interactive winlogon process, duplicated into the
  caller's session.
- TrustedInstaller: the token of the running TrustedInstaller service, with the
  service started first if needed, duplicated into the caller's session.

## Window

`XSudo.exe` started with no arguments (a double-click, or the Start menu
shortcut "XSudo") opens a window instead of running cmd.exe. It needs
administrator rights: started unelevated, it restarts itself through the UAC
prompt and exits. A second start brings the open window to the front.

The window keeps a list of programs and runs them as TrustedInstaller with
every privilege enabled, the same identity as `-TI -P`. Each row has a file,
parameters, a start directory (empty means the file's folder) and a window
state (Normal, Hidden, Minimized, Maximized). Environment variables such as
`%SystemRoot%` are stored as typed and expanded when the row runs. `.bat` and
`.cmd` files run through `cmd.exe /c`, `.ps1` through
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File`, `.msc` through
`mmc.exe`; everything else is started directly. A console program gets its own
console, and XSudo does not wait for it. Two toolbar buttons start Registry
Editor and Command Prompt the same way.

Rows are added with Add (or by dropping files on the window), changed with
Edit, reordered with Move Up and Move Down (Ctrl+Up, Ctrl+Down) and removed
with Remove (Delete, after a confirmation). Double-click or Enter runs a row.
The edit dialog's Run button runs the current values without saving them.

The list and the window position are saved per user in
`%APPDATA%\XSudo\XSudo.ini` (UTF-8 with BOM; UTF-16 is read too). A missing
file starts with Command Prompt and Registry Editor as examples; a damaged file
starts with an empty list.

Options, "Add the TrustedInstaller entries to the Explorer right-click menu",
turns the right-click entries below on or off, with the same code as
`--ContextMenu`. The checkmark reads the registry.

## Explorer right-click entries

`XSudo --ContextMenu=On` (or the window's Options item) adds these entries, all
under the key name `XSudoRunAsTI` in
`HKLM\SOFTWARE\Classes\<type>\shell\XSudoRunAsTI`, each with the XSudo icon and
the administrator shield:

| Type | Entry | Command |
| --- | --- | --- |
| `exefile`, `batfile`, `cmdfile`, `Microsoft.PowerShellScript.1`, `mscfile` | Run as TrustedInstaller | `"<this XSudo.exe>" --Launch "%1"` |
| `regfile` | Import as TrustedInstaller | `"<this XSudo.exe>" --Import "%1"` |
| `Folder` (not the Recycle Bin) | Open as TrustedInstaller | `"<this XSudo.exe>" --OpenFolder "%V"` |

The commands name the XSudo.exe that wrote them, so run the switch from the copy
that stays installed. `--ContextMenu=Off` deletes exactly those keys. When
XSudo had to create a type's `shell` key (or the type's key itself), it records
that in the value `XSudoCreated` of its own key, and turning the entries off
also removes that `shell` key (or type key) if it is then empty; keys that
existed before are never removed. `--ContextMenu` must be the only argument and
needs an elevated prompt; it prints one line and exits 0, or prints an error
and exits with `0x58530001` (bad value), `0x58530002` (not elevated) or
`0x58530004` (a registry write or delete failed).

## --Launch

`XSudo --Launch FILE` (only as the first argument) runs FILE exactly as the
window's Run does, with FILE's folder as the start directory, and returns at
once with exit code 0. Errors are shown in a message box and returned as the
reserved codes above. Unelevated, it restarts itself through the UAC prompt.
Anything after FILE is passed to it as parameters.

## --Import

`XSudo --Import FILE` (only as the first argument) imports the `.reg` file with
`reg.exe import` as TrustedInstaller, waits for it (at most five minutes) and
shows a message box saying it was imported, or the error with reg.exe's own
message and exit code. While reg.exe runs, the SYSTEM profile key
`HKEY_USERS\S-1-5-18` points at the signed-in user's profile, so
`HKEY_CURRENT_USER` lines in the file reach that user, as they did with the
TrustedInstaller entries XOS shipped before; the link is put back to
`\Registry\User\.Default` as soon as reg.exe exits. Unelevated, it restarts
itself through the UAC prompt.

## --OpenFolder

`XSudo --OpenFolder FOLDER` (only as the first argument) opens FOLDER in a new
Explorer window that runs as TrustedInstaller. Explorer's folder windows
normally always run as the signed-in user, because the registration
`HKLM\SOFTWARE\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}` has
`RunAs` = `Interactive User`. XSudo, as TrustedInstaller, empties that value
and points `HKEY_USERS\S-1-5-18` at the signed-in user's profile (so the
window uses that user's Explorer settings), starts `explorer.exe FOLDER` as
TrustedInstaller, waits until the new TrustedInstaller folder window is shown
(at most 30 seconds), and then puts both values back (`Interactive User` and
`\Registry\User\.Default`). The restore does not wait for that Explorer to
exit, so an Explorer process that stays alive after its window is closed
changes nothing. One `XSudo.ShellState` lock serialises `--OpenFolder` and
`--Import`. A drive root such as `"C:\"` is accepted although its trailing
backslash escapes the closing quote. Errors are shown in a message box.

## Build

```
pwsh -File build.ps1
```

This runs `cargo build --release` and prints the binary path, size and SHA-256.
The release binary links the CRT statically and embeds an application manifest
(asInvoker, Windows 10/11, long path aware, common controls 6, per-monitor DPI
aware), the icon, the dialog templates and a version resource. The window uses
plain Win32 through `windows-sys`; there is no GUI framework. `cargo test`
runs the unit tests (command-line parser, ini reader and writer, command
building, environment expansion, right-click entries and their commands, the
`--ContextMenu` switch, folder and import arguments, restore values).

Requires Rust stable with the MSVC toolchain.
