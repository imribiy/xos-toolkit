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
```

With no program, cmd.exe is started. Options are case insensitive. The prefixes
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

## Build

```
pwsh -File build.ps1
```

This runs `cargo build --release` and prints the binary path, size and SHA-256.
The release binary links the CRT statically and embeds an application manifest
(asInvoker, Windows 10/11, long path aware) and a version resource.

Requires Rust stable with the MSVC toolchain.
