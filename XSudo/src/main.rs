#![windows_subsystem = "console"]

mod cli;
mod elevate;
mod exitcode;
mod run;
mod sys;

use cli::Command;
use cli::Mode;
use cli::Outcome;
use cli::Plan;
use exitcode::as_process_code;
use exitcode::ERR_ELEVATION;
use exitcode::ERR_USAGE;

const VERSION_LINE: &str = "XSudo 1.0.0";
const COPYRIGHT_LINE: &str = "(c) 2026 XOS (imribiy)";

fn print_banner() {
    println!("{VERSION_LINE}");
    println!("{COPYRIGHT_LINE}");
}

fn print_version() {
    print_banner();
}

fn print_help() {
    print_banner();
    let text = "\
Run a command with elevated identity in the current console.

Usage:
  XSudo [options] [program] [arguments...]

If no program is given, cmd.exe is started.

Options (names are case insensitive; -, --, and / all work as prefixes):
  --Help, -H, /?            Show this help and exit.
  --Version, -Ver           Show version information and exit.
  --NoLogo, -NoL            Do not print the startup banner.
  --Verbose, -V             Print extra information to stdout.
  --System, -S              Run as NT AUTHORITY\\SYSTEM.
  --TrustedInstaller, -TI   Run as NT SERVICE\\TrustedInstaller.
  --Privileged, -P          Enable every privilege present in the token.
  --WorkDir=PATH, -WD=PATH  Set the child working directory (= or : separates
                            the value; a space does not).

With no mode option the command runs as Administrator. Options that appear
after the program name are passed to the child unchanged.

Exit codes:
  The child's real exit code is returned when it was started and has exited.
  XSudo's own failures use reserved codes: 0x58530001 usage, 0x58530002
  elevation, 0x58530003 identity, 0x58530004 child start, 0x58530005 workdir.";
    println!("{text}");
}

fn print_error(message: &str) {
    eprintln!("[Error] {message}");
}

fn error_message(code: u32) -> &'static str {
    match code {
        exitcode::ERR_IDENTITY => "Could not obtain the requested identity token.",
        exitcode::ERR_CHILD => "Could not start the child process.",
        exitcode::ERR_WORKDIR => "The working directory does not exist or could not be set.",
        exitcode::ERR_ELEVATION => "Could not elevate. The request was declined or failed.",
        _ => "Operation failed.",
    }
}

fn verbose_report(plan: &Plan, cmd: &[u16]) {
    let mode = match plan.mode {
        Mode::Admin => "Administrator",
        Mode::System => "System",
        Mode::TrustedInstaller => "TrustedInstaller",
    };
    let target = match plan.command {
        Command::DefaultShell => "cmd.exe".to_string(),
        Command::Tail(start) => String::from_utf16_lossy(&cli::tail_slice(cmd, start)),
    };
    println!("[Info] Identity: {mode}");
    println!("[Info] Target command line: {target}");
}

fn exit(code: u32) -> ! {
    std::process::exit(as_process_code(code));
}

fn main() {
    sys::install_passthrough_ctrl_handler();
    let raw = sys::get_command_line();
    let (cmd, was_elevated_stage) = elevate::handle_elevated_stage(&raw);

    match cli::parse(&cmd) {
        Outcome::Help => {
            print_help();
            exit(0);
        }
        Outcome::Version => {
            print_version();
            exit(0);
        }
        Outcome::Usage => {
            print_error("Invalid command line. Use --Help for usage.");
            exit(ERR_USAGE);
        }
        Outcome::Launch(plan) => {
            if !sys::is_elevated() {
                if was_elevated_stage {
                    print_error(error_message(ERR_ELEVATION));
                    exit(ERR_ELEVATION);
                }
                match elevate::self_elevate(&cmd) {
                    Ok(code) => exit(code),
                    Err(_) => {
                        print_error(error_message(ERR_ELEVATION));
                        exit(ERR_ELEVATION);
                    }
                }
            }
            if !plan.nologo {
                print_banner();
            }
            if plan.verbose {
                verbose_report(&plan, &cmd);
            }
            match run::run(&plan, &cmd) {
                Ok(code) => exit(code),
                Err(code) => {
                    print_error(error_message(code));
                    exit(code);
                }
            }
        }
    }
}
