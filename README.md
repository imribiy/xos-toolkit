# XOS Toolkit

Windows desktop app for applying XOS tweaks one at a time and undoing them. It includes XOS-CpuService, a small background process that keeps per-process CPU rules applied. Written in Rust with a [Slint](https://slint.dev) interface.

The Toolkit is built for [XOS](https://github.com/imribiy/xos-playbook). It runs on a standard Windows install, but some options rely on services and registry keys that XOS sets up, so functionality is limited there.

## Install

Every [XOS playbook release](https://github.com/imribiy/xos-playbook/releases) installs the Toolkit. To install or update it on its own, download `XOS-Toolkit-Setup-<version>.exe` from [Releases](https://github.com/imribiy/xos-toolkit/releases): the latest stable build, or the newest *Pre-release* for the developer beta. Report problems in [Issues](https://github.com/imribiy/xos-toolkit/issues); search the existing ones first.

The installer upgrades an earlier XOS Toolkit in place, including the old C# versions. The app asks for elevation on launch. XOS-CpuService is installed next to the Toolkit; turn it on from the CPU Affinity page.

## Requirements

- Windows 10 or Windows 11, 64-bit
- Administrator rights

## What it does

Most items show their current state and have their own apply, enable, disable or restore control. You can undo one change without resetting the rest.

- **System:** Defender, UAC, notifications, power savings, the XOS power plan, hibernation, virtualization (VBS/HVCI), Hyper-V, RDP, Windows Search and service grouping.
- **Visuals:** themes, Alt-Tab style, Widgets, shell folder entries, the power plan context menu, Open-Shell and file security prompts.
- **Gaming:** Game Bar, fullscreen and windowed-game optimizations, CPU/GPU priorities, hardware-accelerated GPU scheduling, VRR, Auto HDR, overlays, and Nvidia/AMD GPU tweaks.
- **CPU affinity:** per-process CPU Set or affinity rules through `XOS-CpuService`, with presets for hybrid and multi-CCD CPUs.
- **Network and peripherals:** Wi-Fi, Bluetooth, VPN, adapter tweaks, Edge auto-install, WebView2 install/removal, USB power saving, printing, serial ports and clipboard features.
- **Apps and cleanup:** Chocolatey installs, AppX removal, startup entries, driver store cleanup and disk cleanup.
- **Updates:** update policy, delivery optimization, restart behaviour, Known Game List metadata and root certificates.
- **Repair:** network reset, shell folder repair, time sync, Windows or XOS service defaults, a diagnostic ZIP, and XOS uninstall (on XOS installs).
- **Backup and monitoring:** JSON configuration export/import with a diff preview, and critical/error events from the System and Application logs.

Some changes need a restart. When they do, the app asks for one or restarts the PC.

## XOS-CpuService

The Toolkit creates the rules and the service applies them. A scheduled task named `XOS CPU Service` starts it at sign-in with elevated rights, and it polls for matching processes.

CPU Set is the default and works with most games and anti-cheat software. Affinity is stricter, but most anti-cheats block or override it, and it is limited to 64 logical processors. Presets cover P-cores/E-cores, 3D V-Cache and CCD layouts, and physical or logical cores.

Rules are stored in `%AppData%\XOS Toolkit\CpuRules.json`. The service log is `%ProgramData%\XOS Toolkit\Logs\XOS-CpuService.log`. Turn the service on or off and export or import rules from the CPU Affinity page.

## Repository layout

- `crates/xos-toolkit`: the app (window, pages, installer icon).
- `crates/xos-cpuservice`: the background CPU rule service.
- `crates/xos-page-*`: one crate per Toolkit page.
- `crates/xos-core`, `xos-sys`, `xos-helpers`, `xos-cpu`, `xos-winupdate`, `xos-uninstall`: shared logic.
- `resources/`: data files embedded in the app (power plan, service and registry defaults, NVIDIA profiles, Open-Shell skins).
- `XSudo/`: the elevation helper (Rust), embedded in the app.
- `installer.iss`: the Inno Setup installer script.

## Build

Install:

- [Rust](https://rustup.rs) (stable, MSVC toolchain)
- Visual Studio 2022 Build Tools with the C++ workload (linker and Windows SDK)
- [Inno Setup 6](https://jrsoftware.org/isinfo.php), for the installer only

These files are not in the repository. The app embeds them at compile time, so add them first:

| File | Source | Put it in |
|---|---|---|
| `nvidiaProfileInspector.exe`, `nvidiaProfileInspector.exe.config`, `Reference.xml` | [Nvidia Profile Inspector](https://github.com/Orbmu2k/nvidiaProfileInspector) | `resources/Nvidia Profile Inspector/` |
| `chocolatey-2.7.1.0.msi` (installer only) | [Chocolatey](https://chocolatey.org/install) | `resources/` |

The app also embeds `resources/XSudo.exe`, the elevation helper. It is part of XOS and its source is in `XSudo/`. Build it first with `XSudo\build.ps1 -Install`, which compiles it and copies it to `resources\XSudo.exe`.

Then, from the repository root:

```powershell
cargo build --release --locked -p xos-toolkit -p xos-cpuservice
& "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" installer.iss
```

The executables land in `target\release`, the installer at `target\installer\XOS-Toolkit-Setup.exe`.

## Uninstall

Uninstalling XOS Toolkit removes the app and the `XOS CPU Service` task. It does not undo settings changed by the Toolkit or by XOS. Use the restore controls on each page, or **Troubleshooting > Uninstall XOS**, to return XOS-changed settings to Windows defaults. That does not restore your previous configuration, and removed Store apps have to be reinstalled by hand.

The Toolkit writes to services, drivers, scheduled tasks and the registry. Use it on a system you can reinstall if something goes wrong.

## License

Copyright (c) 2026 XOS (imribiy). Licensed under [CC BY-NC-ND 4.0](LICENSE): you may share it unchanged, with credit, for non-commercial purposes. You may not sell it, use it commercially, or distribute modified or rebranded versions.

## Credits

The app bundles XSudo (part of XOS, source in `XSudo/`), Nvidia Profile Inspector by Orbmu2k, Chocolatey, `DefenderOFF.ps1` (based on LeanAndMean by AveYo, MIT) and the Open-Shell Fluent-Metro skins. Each third-party component keeps its own licence; XSudo is covered by the XOS license.
