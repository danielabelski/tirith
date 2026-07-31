#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AclSource {
    ExistingDestination,
    OwnerOnly,
}

pub(crate) fn acl_source(destination_exists: bool, preserve_destination_dacl: bool) -> AclSource {
    if destination_exists && preserve_destination_dacl {
        AclSource::ExistingDestination
    } else {
        AclSource::OwnerOnly
    }
}

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

pub(crate) fn attributes_are_safe(attributes: u32, expect_directory: bool) -> bool {
    attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
        && ((attributes & FILE_ATTRIBUTE_DIRECTORY != 0) == expect_directory)
}

fn normalized(path: &str) -> String {
    let path = path.replace('/', "\\");
    let path = path
        .strip_prefix(r"\\?\UNC\")
        .map(|rest| format!(r"\\{rest}"))
        .or_else(|| path.strip_prefix(r"\\?\").map(str::to_owned))
        .unwrap_or(path);
    path.trim_end_matches('\\').to_lowercase()
}

pub(crate) fn final_path_within(root: &str, candidate: &str) -> bool {
    let root = normalized(root);
    let candidate = normalized(candidate);
    candidate == root
        || candidate
            .strip_prefix(&root)
            .is_some_and(|suffix| suffix.starts_with('\\'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn containment_is_component_aware_and_case_insensitive() {
        assert!(final_path_within(
            r"\\?\C:\Users\Alice\repo",
            r"c:\users\alice\repo\hooks"
        ));
        assert!(!final_path_within(
            r"C:\Users\Alice\repo",
            r"C:\Users\Alice\repo-escape\hooks"
        ));
    }

    #[test]
    fn containment_normalizes_unc_handle_paths() {
        assert!(final_path_within(
            r"\\?\UNC\server\share\repo",
            r"\\server\share\repo\agents"
        ));
    }

    #[test]
    fn acl_policy_preserves_existing_and_hardens_new_files() {
        assert_eq!(acl_source(true, true), AclSource::ExistingDestination);
        assert_eq!(acl_source(false, true), AclSource::OwnerOnly);
        assert_eq!(acl_source(true, false), AclSource::OwnerOnly);
    }

    #[test]
    fn reparse_components_are_rejected_for_directories_and_files() {
        assert!(!attributes_are_safe(
            FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT,
            true
        ));
        assert!(!attributes_are_safe(FILE_ATTRIBUTE_REPARSE_POINT, false));
        assert!(attributes_are_safe(FILE_ATTRIBUTE_DIRECTORY, true));
        assert!(attributes_are_safe(0, false));
    }
}
