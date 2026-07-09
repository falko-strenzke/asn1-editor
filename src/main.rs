use std::path::PathBuf;
use std::process::ExitCode;

use asn1_editor::{app::App, ber, dump, input, tui};

const USAGE: &str = "\
Usage: asn1-editor [OPTIONS] <FILE>

TUI ASN.1 (BER/DER) viewer and editor. Accepts raw DER/BER, PEM,
base64 and hex input files.

Options:
  -d, --dump        print a dumpasn1-style dump instead of starting the TUI
  -o, --out FILE    write edits to FILE instead of overwriting the input
  -h, --help        show this help
";

fn main() -> ExitCode {
    let mut dump_mode = false;
    let mut out_path: Option<PathBuf> = None;
    let mut file: Option<PathBuf> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{}", USAGE);
                return ExitCode::SUCCESS;
            }
            "-d" | "--dump" => dump_mode = true,
            "-o" | "--out" => match args.next() {
                Some(p) => out_path = Some(PathBuf::from(p)),
                None => return usage_error("missing argument for --out"),
            },
            _ if arg.starts_with('-') => {
                return usage_error(&format!("unknown option '{}'", arg));
            }
            _ => {
                if file.is_some() {
                    return usage_error("more than one input file given");
                }
                file = Some(PathBuf::from(arg));
            }
        }
    }
    let Some(path) = file else {
        return usage_error("no input file given");
    };

    let raw = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => return fail(&format!("cannot read {}: {}", path.display(), e)),
    };
    let (der, container) = match input::load(&raw) {
        Ok(r) => r,
        Err(e) => return fail(&format!("{}: {}", path.display(), e)),
    };
    let roots = match ber::parse_forest(&der, 0) {
        Ok(r) => r,
        Err(e) => return fail(&format!("{}: ASN.1 parse error at {}", path.display(), e)),
    };

    if dump_mode {
        print!("{}", dump::dump(&roots, der.len()));
        return ExitCode::SUCCESS;
    }

    let out_path = out_path.unwrap_or_else(|| path.clone());
    let app = App::new(path, out_path, container, roots, der.len());
    match tui::run(app) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(&format!("terminal error: {}", e)),
    }
}

fn usage_error(msg: &str) -> ExitCode {
    eprintln!("error: {}\n\n{}", msg, USAGE);
    ExitCode::FAILURE
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("error: {}", msg);
    ExitCode::FAILURE
}
