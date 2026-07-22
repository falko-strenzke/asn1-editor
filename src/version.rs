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

//! How this binary identifies itself — the menu's "About ▸ Version" entry.
//!
//! Two kinds of build are distinguished, from what `build.rs` recorded:
//!
//! * An **official** build is one made from a commit carrying a git tag, with
//!   nothing modified on top of it. It is identified by that tag's version
//!   number, which names a reproducible state of the sources and is what a bug
//!   report should quote.
//! * Every other build is a **general** (development) build. There is no
//!   meaningful version number for it, so it is identified by the abbreviated
//!   commit it was built from — plus a note when the working tree had
//!   uncommitted changes, in which case even the commit does not fully
//!   describe the binary.
//!
//! The public functions read what this build recorded; the ones they delegate
//! to take that state as arguments, so every combination can be tested rather
//! than only whichever one the test run happens to have been built in.

/// The version from `Cargo.toml`. On its own this says only which release the
/// sources are *heading for*, which is why an untagged build is identified by
/// its commit instead.
pub const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The git tag HEAD sat on at build time, or empty.
static TAG: &str = env!("BUILD_TAG");
/// The abbreviated commit HEAD pointed at, or empty.
static COMMIT: &str = env!("BUILD_COMMIT");
/// Non-empty when tracked files differed from that commit.
static MODIFIED: &str = env!("BUILD_MODIFIED");

/// Whether this is an officially versioned build.
pub fn is_official() -> bool {
    official(TAG, MODIFIED)
}

/// The one-line build identity: a version number for an official build, an
/// abbreviated commit for a general one.
pub fn build_id() -> String {
    id(TAG, COMMIT, MODIFIED)
}

/// The lines of the "Version" popup: what this build is, and how to read that.
pub fn describe() -> Vec<String> {
    description(TAG, COMMIT, MODIFIED)
}

fn official(tag: &str, modified: &str) -> bool {
    !tag.is_empty() && modified.is_empty()
}

fn id(tag: &str, commit: &str, modified: &str) -> String {
    let suffix = if modified.is_empty() { "" } else { " + uncommitted changes" };
    match (tag, commit) {
        ("", "") => format!("{} (no build metadata)", PACKAGE_VERSION),
        ("", commit) => format!("commit {}{}", commit, suffix),
        (tag, _) => format!("{}{}", tag, suffix),
    }
}

fn description(tag: &str, commit: &str, modified: &str) -> Vec<String> {
    let mut lines = vec![format!("asn1-editor {}", id(tag, commit, modified)), String::new()];
    if official(tag, modified) {
        lines.push(format!(
            "This is an official build: it was made from the tagged release {}, so the \
             version number identifies the sources exactly.",
            tag
        ));
    } else if commit.is_empty() {
        lines.push(format!(
            "No git metadata was available when this binary was built (the sources were not \
             a checkout), so it can only be identified by the package version it was cut \
             from: {}.",
            PACKAGE_VERSION
        ));
    } else {
        lines.push(format!(
            "This is a general build, not an official release, so it has no version number \
             of its own. It was built from commit {} of the source repository — quote that \
             commit when reporting a problem.",
            commit
        ));
        if !tag.is_empty() {
            lines.push(format!(
                "That commit does carry the tag {}, but tracked files were modified on top of \
                 it, so this binary is not that release.",
                tag
            ));
        } else if !modified.is_empty() {
            lines.push(
                "Tracked files were modified on top of that commit, so the commit alone does \
                 not fully describe this binary."
                    .to_string(),
            );
        }
    }
    lines.push(String::new());
    lines.push(format!("Package version: {}", PACKAGE_VERSION));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tagged_clean_build_is_official_and_shows_its_version() {
        assert!(official("v1.2.3", ""));
        assert_eq!(id("v1.2.3", "abc1234", ""), "v1.2.3");
        let text = description("v1.2.3", "abc1234", "").join("\n");
        assert!(text.contains("official build"), "{text}");
        assert!(text.contains("tagged release v1.2.3"), "{text}");
        assert!(!text.contains("abc1234"), "an official build is named by its tag:\n{text}");
    }

    #[test]
    fn an_untagged_build_is_identified_by_its_commit() {
        assert!(!official("", ""));
        assert_eq!(id("", "abc1234", ""), "commit abc1234");
        let text = description("", "abc1234", "").join("\n");
        assert!(text.contains("general build"), "{text}");
        assert!(text.contains("commit abc1234"), "{text}");
    }

    /// A modified working tree disqualifies a build however it is tagged: the
    /// binary is not the release the tag names.
    #[test]
    fn a_modified_working_tree_is_never_official() {
        assert!(!official("v1.2.3", "1"));
        assert_eq!(id("v1.2.3", "abc1234", "1"), "v1.2.3 + uncommitted changes");
        let tagged = description("v1.2.3", "abc1234", "1").join("\n");
        assert!(tagged.contains("general build"), "{tagged}");
        assert!(tagged.contains("is not that release"), "{tagged}");

        let untagged = description("", "abc1234", "1").join("\n");
        assert_eq!(id("", "abc1234", "1"), "commit abc1234 + uncommitted changes");
        assert!(untagged.contains("does not fully describe this binary"), "{untagged}");
    }

    /// Built outside a checkout — a release tarball, a vendored copy — there is
    /// nothing but the package version to go on, and the popup says so.
    #[test]
    fn a_build_without_git_metadata_falls_back_to_the_package_version() {
        assert!(!official("", ""));
        assert_eq!(id("", "", ""), format!("{} (no build metadata)", PACKAGE_VERSION));
        let text = description("", "", "").join("\n");
        assert!(text.contains("No git metadata"), "{text}");
        assert!(text.contains(PACKAGE_VERSION));
    }

    /// Whatever state *this* build is in, its own strings are consistent.
    #[test]
    fn this_build_describes_itself_consistently() {
        let text = describe().join("\n");
        assert!(text.contains(&build_id()), "the popup states the build id:\n{text}");
        assert!(text.contains(PACKAGE_VERSION));
        assert_eq!(is_official(), text.contains("official build"));
    }
}
