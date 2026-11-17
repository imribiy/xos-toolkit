use windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE;

use crate::reg;

pub const VERB: &str = "XSudoRunAsTI";
pub const CREATED_VALUE: &str = "XSudoCreated";
pub const RECYCLE_BIN_EXCLUDED: &str =
    "NOT System.ParsingName:=\"::{645FF040-5081-101B-9F08-00AA002F954E}\"";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verb {
    pub class: &'static str,
    pub label: &'static str,
    pub switch: &'static str,
    pub placeholder: &'static str,
    pub applies_to: Option<&'static str>,
}

const fn run(class: &'static str) -> Verb {
    Verb {
        class,
        label: "Run as TrustedInstaller",
        switch: "--Launch",
        placeholder: "%1",
        applies_to: None,
    }
}

pub const VERBS: [Verb; 7] = [
    run("exefile"),
    run("batfile"),
    run("cmdfile"),
    run("Microsoft.PowerShellScript.1"),
    run("mscfile"),
    Verb {
        class: "regfile",
        label: "Import as TrustedInstaller",
        switch: "--Import",
        placeholder: "%1",
        applies_to: None,
    },
    Verb {
        class: "Folder",
        label: "Open as TrustedInstaller",
        switch: "--OpenFolder",
        placeholder: "%V",
        applies_to: Some(RECYCLE_BIN_EXCLUDED),
    },
];

pub fn class_path(class: &str) -> String {
    format!("SOFTWARE\\Classes\\{class}")
}

pub fn shell_path(class: &str) -> String {
    format!("SOFTWARE\\Classes\\{class}\\shell")
}

pub fn key_path(class: &str) -> String {
    format!("SOFTWARE\\Classes\\{class}\\shell\\{VERB}")
}

pub fn command_string(exe: &str, verb: &Verb) -> String {
    format!("\"{exe}\" {} \"{}\"", verb.switch, verb.placeholder)
}

pub fn created_marker(class_existed: bool, shell_existed: bool) -> Option<&'static str> {
    if !class_existed {
        Some("class")
    } else if !shell_existed {
        Some("shell")
    } else {
        None
    }
}

pub fn parents_to_remove(class: &str, marker: Option<&str>) -> Vec<String> {
    match marker.map(|m| m.trim().to_ascii_lowercase()) {
        Some(m) if m == "class" => vec![shell_path(class), class_path(class)],
        Some(m) if m == "shell" => vec![shell_path(class)],
        _ => Vec::new(),
    }
}

pub fn is_enabled(exe: &str) -> bool {
    VERBS.iter().all(|v| {
        reg::read_string_at(
            HKEY_LOCAL_MACHINE,
            &format!("{}\\command", key_path(v.class)),
            "",
        )
        .map(|c| c.eq_ignore_ascii_case(&command_string(exe, v)))
        .unwrap_or(false)
    })
}

pub fn enable(exe: &str) -> Result<(), u32> {
    for v in VERBS.iter() {
        let path = key_path(v.class);
        let marker = if reg::exists(HKEY_LOCAL_MACHINE, &path) {
            None
        } else {
            created_marker(
                reg::exists(HKEY_LOCAL_MACHINE, &class_path(v.class)),
                reg::exists(HKEY_LOCAL_MACHINE, &shell_path(v.class)),
            )
        };
        let key = reg::create(HKEY_LOCAL_MACHINE, &path)?;
        if let Some(m) = marker {
            reg::set_string(&key, CREATED_VALUE, m)?;
        }
        reg::set_string(&key, "MUIVerb", v.label)?;
        reg::set_string(&key, "Icon", exe)?;
        reg::set_string(&key, "HasLUAShield", "")?;
        if let Some(rule) = v.applies_to {
            reg::set_string(&key, "AppliesTo", rule)?;
        }
        let cmd = reg::create(HKEY_LOCAL_MACHINE, &format!("{path}\\command"))?;
        reg::set_string(&cmd, "", &command_string(exe, v))?;
    }
    Ok(())
}

pub fn disable() -> Result<(), u32> {
    let mut first_error = None;
    for v in VERBS.iter() {
        let path = key_path(v.class);
        let marker = reg::read_string_at(HKEY_LOCAL_MACHINE, &path, CREATED_VALUE);
        let mut result = reg::delete_tree(HKEY_LOCAL_MACHINE, &path);
        if result.is_ok() {
            for parent in parents_to_remove(v.class, marker.as_deref()) {
                result = reg::delete_empty(HKEY_LOCAL_MACHINE, &parent);
                if result.is_err() {
                    break;
                }
            }
        }
        if let Err(e) = result {
            first_error.get_or_insert(e);
        }
    }
    match first_error {
        None => Ok(()),
        Some(e) => Err(e),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Switch {
    On,
    Off,
    Invalid,
}

pub fn parse_switch(text: &str) -> Option<Switch> {
    let name = "--ContextMenu";
    match text.get(..name.len()) {
        Some(head) if head.eq_ignore_ascii_case(name) => {}
        _ => return None,
    }
    let rest = &text[name.len()..];
    if rest.is_empty() {
        return Some(Switch::Invalid);
    }
    if !rest.starts_with(['=', ':']) {
        return None;
    }
    let value = &rest[1..];
    Some(if value.eq_ignore_ascii_case("on") {
        Switch::On
    } else if value.eq_ignore_ascii_case("off") {
        Switch::Off
    } else {
        Switch::Invalid
    })
}

pub const ADDED: &str = "The TrustedInstaller entries were added to the Explorer right-click menu.";
pub const REMOVED: &str =
    "The TrustedInstaller entries were removed from the Explorer right-click menu.";
pub const ADD_FAILED: &str = "The TrustedInstaller entries could not be added to the Explorer right-click menu.";
pub const REMOVE_FAILED: &str =
    "The TrustedInstaller entries could not be removed from the Explorer right-click menu.";

pub fn apply(on: bool, exe: &str) -> Result<(), u32> {
    if on {
        let result = enable(exe);
        if result.is_err() {
            let _ = disable();
        }
        result
    } else {
        disable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXE: &str = "C:\\Program Files\\XSudo\\XSudo.exe";

    #[test]
    fn verb_list_covers_the_seven_classes() {
        let keys: Vec<String> = VERBS.iter().map(|v| key_path(v.class)).collect();
        assert_eq!(
            keys,
            [
                "SOFTWARE\\Classes\\exefile\\shell\\XSudoRunAsTI",
                "SOFTWARE\\Classes\\batfile\\shell\\XSudoRunAsTI",
                "SOFTWARE\\Classes\\cmdfile\\shell\\XSudoRunAsTI",
                "SOFTWARE\\Classes\\Microsoft.PowerShellScript.1\\shell\\XSudoRunAsTI",
                "SOFTWARE\\Classes\\mscfile\\shell\\XSudoRunAsTI",
                "SOFTWARE\\Classes\\regfile\\shell\\XSudoRunAsTI",
                "SOFTWARE\\Classes\\Folder\\shell\\XSudoRunAsTI",
            ]
        );
        let labels: Vec<&str> = VERBS.iter().map(|v| v.label).collect();
        assert_eq!(
            labels,
            [
                "Run as TrustedInstaller",
                "Run as TrustedInstaller",
                "Run as TrustedInstaller",
                "Run as TrustedInstaller",
                "Run as TrustedInstaller",
                "Import as TrustedInstaller",
                "Open as TrustedInstaller",
            ]
        );
        assert!(VERBS[..6].iter().all(|v| v.applies_to.is_none()));
        assert_eq!(
            VERBS[6].applies_to,
            Some("NOT System.ParsingName:=\"::{645FF040-5081-101B-9F08-00AA002F954E}\"")
        );
    }

    #[test]
    fn commands_quote_exe_and_argument() {
        let cmds: Vec<String> = VERBS.iter().map(|v| command_string(EXE, v)).collect();
        assert_eq!(
            cmds[0],
            "\"C:\\Program Files\\XSudo\\XSudo.exe\" --Launch \"%1\""
        );
        assert!(cmds[..5].iter().all(|c| c == &cmds[0]));
        assert_eq!(
            cmds[5],
            "\"C:\\Program Files\\XSudo\\XSudo.exe\" --Import \"%1\""
        );
        assert_eq!(
            cmds[6],
            "\"C:\\Program Files\\XSudo\\XSudo.exe\" --OpenFolder \"%V\""
        );
    }

    #[test]
    fn expanded_commands_round_trip_through_the_parser() {
        for (v, arg) in [
            (&VERBS[1], "C:\\a b\\t.bat"),
            (&VERBS[5], "C:\\my files\\tweak one.reg"),
            (&VERBS[6], "C:\\Program Files (x86)\\x y"),
        ] {
            let cmd = command_string(EXE, v).replace(v.placeholder, arg);
            let wide: Vec<u16> = cmd.encode_utf16().collect();
            let t = crate::cli::tokenize(&wide);
            assert_eq!(t.len(), 3, "{cmd}");
            assert_eq!(t[0].text, EXE);
            assert_eq!(t[1].text, v.switch);
            assert_eq!(t[2].text, arg);
        }
    }

    #[test]
    fn created_parents_are_recorded_and_removed_only_when_recorded() {
        assert_eq!(created_marker(true, true), None);
        assert_eq!(created_marker(true, false), Some("shell"));
        assert_eq!(created_marker(false, false), Some("class"));
        assert_eq!(created_marker(false, true), Some("class"));
        let c = "Microsoft.PowerShellScript.1";
        assert!(parents_to_remove(c, None).is_empty());
        assert!(parents_to_remove(c, Some("other")).is_empty());
        assert_eq!(
            parents_to_remove(c, Some("shell")),
            ["SOFTWARE\\Classes\\Microsoft.PowerShellScript.1\\shell"]
        );
        assert_eq!(
            parents_to_remove(c, Some("Class")),
            [
                "SOFTWARE\\Classes\\Microsoft.PowerShellScript.1\\shell",
                "SOFTWARE\\Classes\\Microsoft.PowerShellScript.1",
            ]
        );
    }

    #[test]
    fn switch_parsing() {
        assert_eq!(parse_switch("--ContextMenu=On"), Some(Switch::On));
        assert_eq!(parse_switch("--contextmenu:off"), Some(Switch::Off));
        assert_eq!(parse_switch("--CONTEXTMENU=ON"), Some(Switch::On));
        assert_eq!(parse_switch("--ContextMenu"), Some(Switch::Invalid));
        assert_eq!(parse_switch("--ContextMenu="), Some(Switch::Invalid));
        assert_eq!(parse_switch("--ContextMenu=yes"), Some(Switch::Invalid));
        assert_eq!(parse_switch("--ContextMenu= On"), Some(Switch::Invalid));
        assert_eq!(parse_switch("--ContextMenus=On"), None);
        assert_eq!(parse_switch("-ContextMenu=On"), None);
        assert_eq!(parse_switch("/ContextMenu=On"), None);
        assert_eq!(parse_switch("--Launch"), None);
        assert_eq!(parse_switch("--Context"), None);
    }
}
