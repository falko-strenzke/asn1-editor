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

//! Records how this binary was built, for the menu's "Version" entry
//! (`src/version.rs` turns the three variables into the displayed text):
//!
//! * `BUILD_TAG` — the git tag HEAD sits exactly on, if any. Its presence is
//!   what makes a build an *official*, versioned one.
//! * `BUILD_COMMIT` — the abbreviated commit HEAD points at, which identifies
//!   every other ("general") build.
//! * `BUILD_MODIFIED` — non-empty when the working tree had uncommitted
//!   changes, so a build that does not match its commit says so.
//!
//! All three are empty when git is unavailable or the source is not a
//! checkout (a release tarball, a vendored copy); the version text falls back
//! to the package version alone.

use std::path::Path;
use std::process::Command;

fn main() {
    // Rebuild when HEAD moves or is re-pointed, so the recorded commit cannot
    // go stale. Naming a path that does not exist would force a rebuild every
    // time, so only existing ones are declared.
    for path in [".git/HEAD", ".git/refs", ".git/index"] {
        if Path::new(path).exists() {
            println!("cargo:rerun-if-changed={}", path);
        }
    }
    println!("cargo:rustc-env=BUILD_TAG={}", git(&["describe", "--tags", "--exact-match", "HEAD"]));
    println!("cargo:rustc-env=BUILD_COMMIT={}", git(&["rev-parse", "--short", "HEAD"]));
    let modified = !git(&["status", "--porcelain", "--untracked-files=no"]).is_empty();
    println!("cargo:rustc-env=BUILD_MODIFIED={}", if modified { "1" } else { "" });
}

/// The trimmed stdout of a successful `git` invocation, or the empty string —
/// a failure here (no git, no checkout, no tag) is an expected outcome, not an
/// error: it simply means that piece of build identity is unknown.
fn git(args: &[&str]) -> String {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .unwrap_or_default()
}
