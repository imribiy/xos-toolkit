use windows::core::PCWSTR;
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Locate_DevNodeW, CM_Reenumerate_DevNode, CM_LOCATE_DEVNODE_FLAGS, CM_REENUMERATE_FLAGS,
};

use crate::elevation::run_as_ti;
use crate::misc::get_windows_build_number;
use crate::process::{run_cmd_opts, run_cmd_timeout, CmdOptions};
use crate::util::{encode_command, escape_powershell_literal};
use xos_core::log;

const DEVICE_NEEDS_RESTART_EXIT_CODES: [i32; 2] = [1167, 50];

pub fn set_pnp_devices(enable: bool, filter_expr: &str, rescan_on_enable: bool) -> bool {
    let verb = if enable { "Enable" } else { "Disable" };
    let mut rescan = String::new();
    if enable && rescan_on_enable {
        if get_windows_build_number() >= 19041 {
            rescan = "& pnputil.exe /scan-devices | Out-Null; ".to_string();
        } else {
            rescan_pnp_device_tree();
        }
    }
    let script = format!(
        "$ErrorActionPreference='Stop';{rescan}\
$devices=@(Get-PnpDevice -ErrorAction Stop | Where-Object {{{filter_expr}}});\
$failed=$false;\
foreach($device in $devices){{try{{$device | {verb}-PnpDevice -Confirm:$false -ErrorAction Stop | Out-Null}}catch{{$failed=$true}}}};\
if($failed){{exit 1}}"
    );
    run_as_ti(
        "powershell.exe",
        &format!(
            "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {}",
            encode_command(&script)
        ),
    )
}

pub fn enable_device(instance_id: &str, allow_missing_device: bool) -> bool {
    if get_windows_build_number() >= 19041 {
        return run_cmd_opts(
            "pnputil.exe",
            &format!("/enable-device \"{instance_id}\""),
            &CmdOptions {
                accepted_exit_codes: if allow_missing_device {
                    &DEVICE_NEEDS_RESTART_EXIT_CODES
                } else {
                    &[]
                },
                ..Default::default()
            },
        );
    }
    set_pnp_device_legacy(instance_id, true)
}

pub fn disable_device(instance_id: &str, allow_missing_device: bool) -> bool {
    if get_windows_build_number() >= 19041 {
        return run_cmd_opts(
            "pnputil.exe",
            &format!("/disable-device \"{instance_id}\""),
            &CmdOptions {
                accepted_exit_codes: if allow_missing_device {
                    &DEVICE_NEEDS_RESTART_EXIT_CODES
                } else {
                    &[]
                },
                ..Default::default()
            },
        );
    }
    set_pnp_device_legacy(instance_id, false)
}

fn set_pnp_device_legacy(instance_id: &str, enable: bool) -> bool {
    if instance_id.trim().is_empty() {
        return false;
    }
    let verb = if enable { "Enable" } else { "Disable" };
    let script = format!(
        "$ErrorActionPreference='Stop';$id='{}';$d=Get-PnpDevice -ErrorAction Stop|Where-Object{{$_.InstanceId -eq $id}};if($null -eq $d){{exit 1}};$d|{verb}-PnpDevice -Confirm:$false -ErrorAction Stop",
        escape_powershell_literal(instance_id)
    );
    run_cmd_timeout(
        "powershell.exe",
        &format!(
            "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {}",
            encode_command(&script)
        ),
        60000,
    )
}

fn rescan_pnp_device_tree() {
    let mut root: u32 = 0;
    let mut status =
        unsafe { CM_Locate_DevNodeW(&mut root, PCWSTR::null(), CM_LOCATE_DEVNODE_FLAGS(0)) }.0;
    if status == 0 {
        status = unsafe { CM_Reenumerate_DevNode(root, CM_REENUMERATE_FLAGS(0)) }.0;
    }
    if status != 0 {
        log::log(&format!(
            "[PnP] Device-tree rescan failed with CONFIGRET 0x{status:X}."
        ));
    }
}
