//! Shared set of built-in build-artifact directory names.
//!
//! These are directories that contain generated or vendored output rather than
//! authored source. The scanner skips them during directory walks, and a later
//! correlation pass reuses the same set so the two stay in agreement.

/// Directory basenames treated as build artifacts / generated output.
///
/// Skipping these avoids scanning machine-generated files and keeps walks fast.
pub const BUILT_IN_SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "__pycache__",
    ".tox",
    "dist",
    "build",
    ".next",
    "vendor",
    ".cache",
    "out",
    ".turbo",
    "coverage",
    ".expo",
];

/// Returns true if `name` (a directory basename) is a built-in build-artifact
/// directory that should be skipped during scanning.
pub fn should_skip_dir(name: &str) -> bool {
    BUILT_IN_SKIP_DIRS.contains(&name)
}

/// Returns true if any component of `path` is a built-in build-artifact
/// directory. Components are split on both `/` and `\` so the check works for
/// POSIX and Windows-style paths. Dot components are normalized lexically
/// before classification: a canceled `dist/..` must not exempt the real target,
/// and an unresolved upward traversal is never trusted as generated output.
pub fn is_build_artifact_path(path: &str) -> bool {
    let mut components: Vec<&str> = Vec::new();
    for component in path.split(['/', '\\']) {
        match component {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return false;
                }
            }
            name => components.push(name),
        }
    }
    components.into_iter().any(should_skip_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_dirs_are_members() {
        for name in ["out", ".turbo", "coverage", ".expo"] {
            assert!(should_skip_dir(name), "{name} should be a skip dir");
        }
    }

    #[test]
    fn original_dirs_still_members() {
        for name in [
            ".git",
            "node_modules",
            "target",
            "__pycache__",
            ".tox",
            "dist",
            "build",
            ".next",
            "vendor",
            ".cache",
        ] {
            assert!(should_skip_dir(name), "{name} should be a skip dir");
        }
    }

    #[test]
    fn non_build_dirs_are_not_members() {
        assert!(!should_skip_dir("src"));
        assert!(!should_skip_dir(".vscode"));
    }

    #[test]
    fn build_artifact_path_detection() {
        assert!(is_build_artifact_path("a/dist/b.js"));
        assert!(!is_build_artifact_path("src/main.rs"));
    }

    #[test]
    fn build_artifact_path_handles_backslashes() {
        assert!(is_build_artifact_path("a\\node_modules\\b.js"));
    }

    #[test]
    fn build_artifact_path_normalizes_canceled_components() {
        assert!(is_build_artifact_path("src/../dist/bundle.js"));
        assert!(!is_build_artifact_path("dist/../src/main.rs"));
        assert!(!is_build_artifact_path("build/./../src/lib.rs"));
    }

    #[test]
    fn build_artifact_path_rejects_unresolved_parent_traversal() {
        assert!(!is_build_artifact_path("../dist/bundle.js"));
        assert!(!is_build_artifact_path("dist/../../dist/bundle.js"));
    }
}
