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

Options, "Add 'Run as TrustedInstaller' to the Explorer right-click menu", adds
that entry for `.exe`, `.bat`, `.cmd` and `.ps1` files under
`HKLM\SOFTWARE\Classes\<type>\shell\XSudoRunAsTI` (types `exefile`,
`batfile`, `cmdfile`, `Microsoft.PowerShellScript.1`), with the command
`"<path of this XSudo.exe>" --Launch "%1"`. It is off by default; turning it
off deletes exactly those keys. The checkmark reads the registry.

## --Launch

`XSudo --Launch FILE` (only as the first argument) runs FILE exactly as the
window's Run does, with FILE's folder as the start directory, and returns at
once with exit code 0. Errors are shown in a message box and returned as the
reserved codes above. Unelevated, it restarts itself through the UAC prompt.
Anything after FILE is passed to it as parameters.

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
building, environment expansion, right-click command).

Requires Rust stable with the MSVC toolchain.
