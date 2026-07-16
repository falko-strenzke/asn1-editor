// Copyright 2026 Falko Strenzke
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::path::PathBuf;
use std::process::ExitCode;

use asn1_editor::{app::App, ber, dump, input, spec, tui};

const USAGE: &str = "\
Usage: asn1-editor [OPTIONS] <FILE|DIR>

TUI ASN.1 (BER/DER) viewer and editor. Accepts raw DER/BER, PEM,
base64 and hex input files.

Given a single file, only that file is opened (single-file mode): no
other files are looked at, the file browser pane is hidden and the
re-signing / re-keying actions are unavailable. Given a directory
instead, it starts with the file browser pane showing that directory
and no document loaded; pick a file from it (Enter) to open it, with
the full cross-file features (relation arrows, key links, re-signing).

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

    if path.is_dir() {
        if dump_mode {
            return usage_error("--dump requires a file, not a directory");
        }
        if out_path.is_some() {
            return usage_error("--out requires a file, not a directory");
        }
        let mut app = App::new_dir(path);
        load_specs_into(&mut app);
        return match tui::run(app) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&format!("terminal error: {}", e)),
        };
    }

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
    // An explicit file argument opens exactly that file: single-file mode, with
    // no directory scan, no browser pane and no re-signing / re-keying.
    let mut app = App::new_single_file(path, out_path, container, roots, der.len());
    load_specs_into(&mut app);
    match tui::run(app) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(&format!("terminal error: {}", e)),
    }
}

/// Load the bundled ASN.1 specifications into `app`. Any per-file parse errors
/// are surfaced as a dismissible start-up popup rather than printed to stderr,
/// which the TUI would immediately overwrite.
fn load_specs_into(app: &mut App) {
    let Some(dir) = spec::default_spec_dir() else { return };
    let (db, errors) = spec::load_dir(&dir);
    if !db.is_empty() {
        app.set_spec_db(db);
    }
    app.report_spec_errors(errors);
}

fn usage_error(msg: &str) -> ExitCode {
    eprintln!("error: {}\n\n{}", msg, USAGE);
    ExitCode::FAILURE
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("error: {}", msg);
    ExitCode::FAILURE
}
