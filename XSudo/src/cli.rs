#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Admin,
    System,
    TrustedInstaller,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    DefaultShell,
    Tail(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub mode: Mode,
    pub privileged: bool,
    pub nologo: bool,
    pub verbose: bool,
    pub workdir: Option<String>,
    pub command: Command,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Help,
    Version,
    Usage,
    Launch(Plan),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub text: String,
    pub start: usize,
}

const SPACE: u16 = 0x20;
const TAB: u16 = 0x09;
const QUOTE: u16 = 0x22;
const BACKSLASH: u16 = 0x5C;

fn is_ws(c: u16) -> bool {
    c == SPACE || c == TAB
}

pub fn tokenize(cmd: &[u16]) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut i = 0usize;
    let len = cmd.len();
    while i < len {
        while i < len && is_ws(cmd[i]) {
            i += 1;
        }
        if i >= len {
            break;
        }
        let start = i;
        let mut units: Vec<u16> = Vec::new();
        let mut in_quotes = false;
        loop {
            if i >= len {
                break;
            }
            let c = cmd[i];
            if c == BACKSLASH {
                let mut slashes = 0usize;
                while i < len && cmd[i] == BACKSLASH {
                    slashes += 1;
                    i += 1;
                }
                if i < len && cmd[i] == QUOTE {
                    units.resize(units.len() + slashes / 2, BACKSLASH);
                    if slashes % 2 == 1 {
                        units.push(QUOTE);
                        i += 1;
                    } else {
                        in_quotes = !in_quotes;
                        i += 1;
                    }
                } else {
                    units.resize(units.len() + slashes, BACKSLASH);
                }
            } else if c == QUOTE {
                if in_quotes && i + 1 < len && cmd[i + 1] == QUOTE {
                    units.push(QUOTE);
                    i += 2;
                } else {
                    in_quotes = !in_quotes;
                    i += 1;
                }
            } else if is_ws(c) && !in_quotes {
                break;
            } else {
                units.push(c);
                i += 1;
            }
        }
        tokens.push(Token {
            text: String::from_utf16_lossy(&units),
            start,
        });
    }
    tokens
}

fn option_prefix_len(text: &str) -> usize {
    if text.starts_with("--") {
        2
    } else if text.starts_with('-') || text.starts_with('/') {
        1
    } else {
        0
    }
}

enum Classified {
    NoLogo,
    Verbose,
    Privileged,
    Mode(Mode),
    WorkDir(String),
    Help,
    Version,
    Unknown,
}

fn classify(text: &str) -> Classified {
    let pfx = option_prefix_len(text);
    if pfx == 0 {
        return Classified::Unknown;
    }
    let body = &text[pfx..];
    let (name_raw, value) = match body.find([':', '=']) {
        Some(p) => (&body[..p], Some(body[p + 1..].to_string())),
        None => (body, None),
    };
    let name = name_raw.to_ascii_lowercase();
    match name.as_str() {
        "nologo" | "nol" => Classified::NoLogo,
        "verbose" | "v" => Classified::Verbose,
        "privileged" | "p" => Classified::Privileged,
        "system" | "s" => Classified::Mode(Mode::System),
        "trustedinstaller" | "ti" => Classified::Mode(Mode::TrustedInstaller),
        "workdir" | "wd" => Classified::WorkDir(value.unwrap_or_default()),
        "version" | "ver" => Classified::Version,
        "help" | "h" | "?" => Classified::Help,
        _ => Classified::Unknown,
    }
}

pub fn parse(cmd: &[u16]) -> Outcome {
    let tokens = tokenize(cmd);
    let args = if tokens.is_empty() {
        &tokens[0..0]
    } else {
        &tokens[1..]
    };

    let mut mode = Mode::Admin;
    let mut privileged = false;
    let mut nologo = false;
    let mut verbose = false;
    let mut workdir: Option<String> = None;
    let mut help = false;
    let mut version = false;
    let mut saw_recognized = false;
    let mut saw_unknown = false;
    let mut end_of_opts = false;
    let mut command_start: Option<usize> = None;

    let mut idx = 0usize;
    while idx < args.len() {
        let t = &args[idx];
        if end_of_opts {
            command_start = Some(t.start);
            break;
        }
        if t.text == "--" {
            end_of_opts = true;
            idx += 1;
            continue;
        }
        if option_prefix_len(&t.text) == 0 {
            command_start = Some(t.start);
            break;
        }
        match classify(&t.text) {
            Classified::NoLogo => {
                nologo = true;
                saw_recognized = true;
            }
            Classified::Verbose => {
                verbose = true;
                saw_recognized = true;
            }
            Classified::Privileged => {
                privileged = true;
                saw_recognized = true;
            }
            Classified::Mode(m) => {
                mode = m;
                saw_recognized = true;
            }
            Classified::WorkDir(v) => {
                if v.is_empty() {
                    saw_unknown = true;
                } else {
                    workdir = Some(v);
                    saw_recognized = true;
                }
            }
            Classified::Help => {
                help = true;
            }
            Classified::Version => {
                version = true;
            }
            Classified::Unknown => {
                saw_unknown = true;
            }
        }
        idx += 1;
    }

    if let Some(start) = command_start {
        return Outcome::Launch(Plan {
            mode,
            privileged,
            nologo,
            verbose,
            workdir,
            command: Command::Tail(start),
        });
    }

    if help {
        return Outcome::Help;
    }
    if version {
        return Outcome::Version;
    }
    if args.is_empty() || saw_recognized {
        return Outcome::Launch(Plan {
            mode,
            privileged,
            nologo,
            verbose,
            workdir,
            command: Command::DefaultShell,
        });
    }
    let _ = saw_unknown;
    Outcome::Usage
}

pub fn tail_slice(cmd: &[u16], start: usize) -> Vec<u16> {
    let mut end = cmd.len();
    while end > start && is_ws(cmd[end - 1]) {
        end -= 1;
    }
    cmd[start..end].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    fn with_arg0(s: &str) -> Vec<u16> {
        let mut v = w("XSudo.exe ");
        v.extend(s.encode_utf16());
        v
    }

    fn launch(s: &str) -> Plan {
        match parse(&with_arg0(s)) {
            Outcome::Launch(p) => p,
            other => panic!("expected launch, got {:?}", other),
        }
    }

    fn tail_text(s: &str) -> String {
        let cmd = with_arg0(s);
        let p = launch(s);
        match p.command {
            Command::Tail(i) => String::from_utf16_lossy(&tail_slice(&cmd, i)),
            Command::DefaultShell => panic!("expected tail"),
        }
    }

    #[test]
    fn tokenize_quoted_start_is_the_quote() {
        let cmd = w("a \"b c\" d");
        let t = tokenize(&cmd);
        assert_eq!(t[1].text, "b c");
        assert_eq!(t[1].start, 2);
    }

    #[test]
    fn tokenize_backslash_quote_rules() {
        let t = tokenize(&w("exe \\\"x\\\" y"));
        assert_eq!(t[1].text, "\"x\"");
        assert_eq!(t[2].text, "y");
    }

    #[test]
    fn help_variants() {
        for s in ["-?", "/?", "--Help", "--HELP", "-h", "-help"] {
            assert_eq!(parse(&with_arg0(s)), Outcome::Help, "{s}");
        }
    }

    #[test]
    fn version_variants() {
        for s in ["--version", "-Ver", "/VER"] {
            assert_eq!(parse(&with_arg0(s)), Outcome::Version, "{s}");
        }
    }

    #[test]
    fn unknown_alone_is_usage() {
        for s in ["--bogus", "/bogus", "--bogus --bogus", "-x", "-", "---"] {
            assert_eq!(parse(&with_arg0(s)), Outcome::Usage, "{s}");
        }
    }

    #[test]
    fn workdir_without_value_alone_is_usage() {
        assert_eq!(parse(&with_arg0("-WD")), Outcome::Usage);
        assert_eq!(parse(&with_arg0("-WD=")), Outcome::Usage);
    }

    #[test]
    fn unknown_before_command_is_ignored() {
        let p = launch("--NoLogo --bogus cmd /c echo x");
        assert!(p.nologo);
        assert_eq!(tail_text("--NoLogo --bogus cmd /c echo x"), "cmd /c echo x");
    }

    #[test]
    fn recognized_plus_unknown_no_command_runs_shell() {
        let p = launch("--NoLogo --bogus");
        assert_eq!(p.command, Command::DefaultShell);
    }

    #[test]
    fn no_args_runs_default_shell() {
        let p = launch("");
        assert_eq!(p.command, Command::DefaultShell);
        assert_eq!(p.mode, Mode::Admin);
    }

    #[test]
    fn single_flag_runs_default_shell() {
        assert_eq!(launch("-P").command, Command::DefaultShell);
        assert!(launch("-P").privileged);
        assert_eq!(launch("-TrustedInstaller").mode, Mode::TrustedInstaller);
        assert_eq!(launch("/System").mode, Mode::System);
    }

    #[test]
    fn modes_and_aliases() {
        assert_eq!(launch("-S whoami").mode, Mode::System);
        assert_eq!(launch("--System whoami").mode, Mode::System);
        assert_eq!(launch("-TI whoami").mode, Mode::TrustedInstaller);
        assert_eq!(launch("--TrustedInstaller whoami").mode, Mode::TrustedInstaller);
        assert!(launch("-P whoami").privileged);
        assert!(launch("--Privileged whoami").privileged);
        assert!(launch("-NoL whoami").nologo);
        assert!(launch("/nologo whoami").nologo);
        assert!(launch("-V whoami").verbose);
    }

    #[test]
    fn prefixes_and_separators_interchangeable() {
        assert_eq!(launch("-WD=C:\\Windows cmd").workdir.as_deref(), Some("C:\\Windows"));
        assert_eq!(launch("/WD:C:\\Windows cmd").workdir.as_deref(), Some("C:\\Windows"));
        assert_eq!(launch("--WorkDir=C:\\Windows cmd").workdir.as_deref(), Some("C:\\Windows"));
        assert_eq!(launch("--workdir:C:\\Windows cmd").workdir.as_deref(), Some("C:\\Windows"));
    }

    #[test]
    fn value_ignored_for_valueless_options() {
        assert!(launch("--nologo=1 cmd").nologo);
        assert!(launch("--NoLogo:1 cmd").nologo);
    }

    #[test]
    fn workdir_space_value_not_consumed() {
        assert_eq!(tail_text("--NoLogo --WorkDir C:\\Windows cmd /c cd"), "C:\\Windows cmd /c cd");
        assert!(launch("--NoLogo --WorkDir C:\\Windows cmd /c cd").workdir.is_none());
    }

    #[test]
    fn workdir_no_value_before_command_ignored() {
        let p = launch("--NoLogo -WD cmd /c cd");
        assert!(p.workdir.is_none());
        assert_eq!(tail_text("--NoLogo -WD cmd /c cd"), "cmd /c cd");
    }

    #[test]
    fn empty_workdir_before_command_ignored() {
        let p = launch("--NoLogo --WorkDir= cmd /c cd");
        assert!(p.workdir.is_none());
        assert_eq!(tail_text("--NoLogo --WorkDir= cmd /c cd"), "cmd /c cd");
    }

    #[test]
    fn help_version_ignored_when_command_present() {
        assert_eq!(tail_text("--NoLogo --version cmd /c echo q"), "cmd /c echo q");
        assert_eq!(tail_text("--NoLogo --help cmd /c echo q"), "cmd /c echo q");
        assert_eq!(tail_text("--version cmd /c echo q"), "cmd /c echo q");
    }

    #[test]
    fn end_of_options_marker() {
        assert_eq!(tail_text("-- cmd /c echo dd"), "cmd /c echo dd");
        assert_eq!(tail_text("-NoLogo -- cmd /c echo dd2"), "cmd /c echo dd2");
    }

    #[test]
    fn options_after_command_are_verbatim() {
        assert_eq!(
            tail_text("--NoLogo cmd /c echo -P --NoLogo"),
            "cmd /c echo -P --NoLogo"
        );
        assert_eq!(
            tail_text("--NoLogo powershell -NoProfile -File \"x\" -P --NoLogo -S -TI -WD=C:\\Windows"),
            "powershell -NoProfile -File \"x\" -P --NoLogo -S -TI -WD=C:\\Windows"
        );
    }

    #[test]
    fn quoting_passed_through_byte_exact() {
        assert_eq!(tail_text("--NoLogo \"powershell\" -NoProfile z"), "\"powershell\" -NoProfile z");
        assert_eq!(tail_text("--NoLogo \"whoami\""), "\"whoami\"");
    }

    #[test]
    fn internal_spaces_preserved_in_tail() {
        assert_eq!(
            tail_text("--NoLogo powershell   -NoProfile    -File   a    b"),
            "powershell   -NoProfile    -File   a    b"
        );
    }

    #[test]
    fn quoted_option_token_recognized() {
        assert_eq!(launch("--NoLogo \"-S\" whoami").mode, Mode::System);
    }

    #[test]
    fn tab_separator() {
        assert_eq!(launch("--NoLogo\t-S whoami").mode, Mode::System);
        assert_eq!(tail_text("--NoLogo\t-S whoami"), "whoami");
    }

    #[test]
    fn case_insensitive_names() {
        assert_eq!(launch("--system WHOAMI").mode, Mode::System);
        assert_eq!(parse(&with_arg0("-VER")), Outcome::Version);
    }
}
