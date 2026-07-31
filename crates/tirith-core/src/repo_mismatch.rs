//! M6 ch6 — registry-claimed repository URL verification (`--online` only).
//!
//! For a package whose registry response carries a `repository_url`, fetch it
//! and verify: (1) parses as a known git host (GitHub/GitLab/Bitbucket),
//! (2) host reachable, (3) hosted manifest names this package. Returns a
//! [`RepoMismatchVerdict`]:
//!  * `Match` — all three checks passed.
//!  * `Mismatch` — host reachable but manifest names a different package, or
//!    the URL parses as non-git.
//!  * `Unverifiable` — no URL, dead host, or transport failure. Emits no
//!    finding by design.

use std::time::Duration;

use crate::package_risk::{RepoMismatchState, RepoMismatchVerdict};
use crate::threatdb::Ecosystem;

/// Default cap on the number of repo-mismatch checks per scan. M6 ch6 const;
/// ch7's `package_policy.repo_mismatch_check_max_packages` replaces this.
pub const DEFAULT_REPO_MISMATCH_CHECK_MAX: u32 = 50;

/// HTTP timeout per request. Short — `--online` is interactive; a verdict of
/// `Unverifiable` on a slow host is better than a hang.
const REQUEST_TIMEOUT_SECS: u64 = 10;
/// Hard cap on the size of the fetched manifest body. A package.json should
/// never approach this.
const MAX_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;

/// Verify a registry-claimed repository URL against `(eco, name)`.
///
/// On any error the verdict defaults to `Unverifiable` with the reason
/// recorded — the rule never fires unless the verdict is positively `Mismatch`.
pub fn verify(repository_url: &str, eco: Ecosystem, name: &str) -> RepoMismatchVerdict {
    let trimmed = sanitize_repo_url(repository_url);
    let host = match parse_known_git_host(&trimmed) {
        Some(h) => h,
        None => {
            return RepoMismatchVerdict {
                state: RepoMismatchState::Unverifiable,
                reason: "the URL does not parse as a known git host (GitHub/GitLab/Bitbucket)"
                    .to_string(),
            };
        }
    };

    let raw_url = match host.raw_manifest_url(eco) {
        Some(u) => u,
        None => {
            return RepoMismatchVerdict {
                state: RepoMismatchState::Unverifiable,
                reason: format!(
                    "no raw-manifest URL is wired for {} on {} yet",
                    eco,
                    host.host_label()
                ),
            };
        }
    };

    if let Err(reason) = crate::url_validate::validate_server_url(&raw_url) {
        return RepoMismatchVerdict {
            state: RepoMismatchState::Unverifiable,
            reason: format!("refusing unsafe repo manifest URL: {reason}"),
        };
    }

    let client = match reqwest::blocking::Client::builder()
        .no_proxy()
        .dns_resolver(crate::ssrf_guard::ssrf_guard_resolver())
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .redirect(crate::ssrf_guard::server_redirect_policy())
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return RepoMismatchVerdict {
                state: RepoMismatchState::Unverifiable,
                reason: format!("could not build HTTP client: {e}"),
            };
        }
    };

    let resp = match client.get(&raw_url).send() {
        Ok(r) => r,
        Err(e) => {
            return RepoMismatchVerdict {
                state: RepoMismatchState::Unverifiable,
                reason: format!("could not reach the repo URL ({e})"),
            };
        }
    };
    if !resp.status().is_success() {
        return RepoMismatchVerdict {
            state: RepoMismatchState::Unverifiable,
            reason: format!(
                "the repo manifest URL returned HTTP {}",
                resp.status().as_u16()
            ),
        };
    }

    use std::io::Read as _;
    let mut buf = Vec::new();
    if resp
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut buf)
        .is_err()
        || buf.len() as u64 > MAX_MANIFEST_BYTES
    {
        return RepoMismatchVerdict {
            state: RepoMismatchState::Unverifiable,
            reason: "the repo manifest exceeded tirith's size cap".to_string(),
        };
    }

    let body = String::from_utf8_lossy(&buf);
    if manifest_names_package(&body, name, eco) {
        RepoMismatchVerdict {
            state: RepoMismatchState::Match,
            reason: format!(
                "the hosted manifest at {raw_url} names this package; provenance verified"
            ),
        }
    } else {
        RepoMismatchVerdict {
            state: RepoMismatchState::Mismatch,
            reason: format!("the hosted manifest at {raw_url} does not mention package '{name}'"),
        }
    }
}

/// Strip `git+` prefixes / `.git` suffixes / `#fragment` tails the registry
/// often embeds in repository fields.
fn sanitize_repo_url(url: &str) -> String {
    let mut s = url.trim().to_string();
    for prefix in ["git+", "ssh+"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.to_string();
        }
    }
    // Convert `git@host:owner/repo.git` to `https://host/owner/repo` so we can
    // attempt a known-host parse.
    if s.starts_with("git@") {
        if let Some(at) = s.find('@') {
            if let Some(colon) = s[at..].find(':') {
                let host = &s[at + 1..at + colon];
                let path = &s[at + colon + 1..];
                s = format!("https://{host}/{path}");
            }
        }
    }
    if let Some(idx) = s.find('#') {
        s.truncate(idx);
    }
    // Trim trailing `.git` (GitHub HTTPS URLs often have this).
    if let Some(rest) = s.strip_suffix(".git") {
        s = rest.to_string();
    }
    s
}

/// A known git host the verifier can fetch a raw manifest from.
struct KnownGitHost {
    namespace: Vec<String>,
    repo: String,
    kind: HostKind,
}

#[derive(Debug, Clone, Copy)]
enum HostKind {
    GitHub,
    GitLab,
    Bitbucket,
}

impl KnownGitHost {
    fn host_label(&self) -> &'static str {
        match self.kind {
            HostKind::GitHub => "github.com",
            HostKind::GitLab => "gitlab.com",
            HostKind::Bitbucket => "bitbucket.org",
        }
    }

    fn raw_manifest_url(&self, eco: Ecosystem) -> Option<String> {
        let manifest = manifest_filename(eco)?;
        let base = match self.kind {
            HostKind::GitHub => "https://raw.githubusercontent.com/",
            HostKind::GitLab => "https://gitlab.com/",
            HostKind::Bitbucket => "https://bitbucket.org/",
        };
        let mut url = url::Url::parse(base).ok()?;
        {
            // `push` percent-encodes each already-validated component, so query
            // delimiters and path separators can never change request identity.
            let mut path = url.path_segments_mut().ok()?;
            path.clear();
            for segment in &self.namespace {
                path.push(segment);
            }
            path.push(&self.repo);
            match self.kind {
                HostKind::GitHub => {
                    path.push("HEAD");
                }
                HostKind::GitLab => {
                    path.push("-");
                    path.push("raw");
                    path.push("HEAD");
                }
                HostKind::Bitbucket => {
                    path.push("raw");
                    path.push("HEAD");
                }
            }
            path.push(manifest);
        }
        Some(url.into())
    }
}

fn manifest_filename(eco: Ecosystem) -> Option<&'static str> {
    match eco {
        Ecosystem::Npm => Some("package.json"),
        Ecosystem::Crates => Some("Cargo.toml"),
        Ecosystem::PyPI => Some("pyproject.toml"),
        Ecosystem::RubyGems => Some("Gemfile"),
        // Other ecosystems have no single conventional repo-root manifest; skip rather than guess.
        _ => None,
    }
}

/// `true` when the manifest text references `name` in a way that's specific
/// to the ecosystem (e.g. `"name": "foo"` for npm).
fn manifest_names_package(manifest: &str, name: &str, eco: Ecosystem) -> bool {
    match eco {
        Ecosystem::Npm => {
            let needle = format!("\"name\": \"{name}\"");
            let needle_no_space = format!("\"name\":\"{name}\"");
            manifest.contains(&needle) || manifest.contains(&needle_no_space)
        }
        Ecosystem::Crates => {
            let needle = format!("name = \"{name}\"");
            manifest.contains(&needle)
        }
        Ecosystem::PyPI => {
            let needle = format!("name = \"{name}\"");
            manifest.contains(&needle)
        }
        Ecosystem::RubyGems => {
            // Gemfile: heuristic substring check.
            manifest.contains(name)
        }
        _ => false,
    }
}

/// Parse `(owner, repo, kind)` from a sanitized URL. Returns `None` when the
/// URL is not a github/gitlab/bitbucket project URL.
fn parse_known_git_host(url: &str) -> Option<KnownGitHost> {
    let parsed = url::Url::parse(url).ok()?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    let kind = match parsed
        .host_str()?
        .trim_end_matches('.')
        .to_ascii_lowercase()
        .as_str()
    {
        "github.com" => HostKind::GitHub,
        "gitlab.com" => HostKind::GitLab,
        "bitbucket.org" => HostKind::Bitbucket,
        _ => return None,
    };

    let mut encoded: Vec<&str> = parsed.path_segments()?.collect();
    if encoded.last().copied() == Some("") {
        encoded.pop();
    }
    let mut components = Vec::with_capacity(encoded.len());
    for segment in encoded {
        if segment.is_empty() {
            // A trailing empty component was removed above; any other empty
            // segment changes path identity and is rejected.
            return None;
        }
        let decoded = percent_encoding::percent_decode_str(segment)
            .decode_utf8()
            .ok()?;
        if !valid_repository_component(&decoded) {
            return None;
        }
        components.push(decoded.into_owned());
    }
    let repo = components.pop()?;
    let repo = repo.strip_suffix(".git").unwrap_or(&repo).to_string();
    if !valid_repository_component(&repo) || components.is_empty() {
        return None;
    }
    // GitLab reserves `-` as the delimiter before project routes such as
    // `/-/raw/`. Check after normalizing the repository's optional `.git`
    // suffix so `-.git` cannot become the reserved route segment later.
    if matches!(kind, HostKind::GitLab)
        && (repo == "-" || components.iter().any(|part| part == "-"))
    {
        return None;
    }
    if !matches!(kind, HostKind::GitLab) && components.len() != 1 {
        return None;
    }
    Some(KnownGitHost {
        namespace: components,
        repo,
        kind,
    })
}

fn valid_repository_component(component: &str) -> bool {
    !component.is_empty()
        && component.len() <= 255
        && !matches!(component, "." | "..")
        && component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_repo_url_handles_git_plus_prefix() {
        assert_eq!(
            sanitize_repo_url("git+https://github.com/o/r.git"),
            "https://github.com/o/r"
        );
    }

    #[test]
    fn sanitize_repo_url_handles_scp_form() {
        assert_eq!(
            sanitize_repo_url("git@github.com:owner/repo.git"),
            "https://github.com/owner/repo"
        );
    }

    #[test]
    fn sanitize_repo_url_strips_fragment() {
        assert_eq!(
            sanitize_repo_url("https://github.com/o/r#readme"),
            "https://github.com/o/r"
        );
    }

    #[test]
    fn parse_known_git_host_github() {
        let h =
            parse_known_git_host("https://github.com/owner/repo").expect("github URL must parse");
        assert_eq!(h.namespace, ["owner"]);
        assert_eq!(h.repo, "repo");
        assert!(matches!(h.kind, HostKind::GitHub));
        assert_eq!(
            h.raw_manifest_url(Ecosystem::Npm).as_deref(),
            Some("https://raw.githubusercontent.com/owner/repo/HEAD/package.json")
        );
    }

    #[test]
    fn parse_known_git_host_models_gitlab_subgroups() {
        let h = parse_known_git_host("https://gitlab.com/group/subgroup/repo.git")
            .expect("GitLab subgroup URL must parse");
        assert_eq!(h.namespace, ["group", "subgroup"]);
        assert_eq!(h.repo, "repo");
        assert_eq!(
            h.raw_manifest_url(Ecosystem::PyPI).as_deref(),
            Some("https://gitlab.com/group/subgroup/repo/-/raw/HEAD/pyproject.toml")
        );
    }

    #[test]
    fn parse_known_git_host_rejects_unknown() {
        assert!(parse_known_git_host("https://example.com/owner/repo").is_none());
    }

    #[test]
    fn parse_known_git_host_rejects_empty_segments() {
        assert!(parse_known_git_host("https://github.com//repo").is_none());
        assert!(parse_known_git_host("https://github.com/owner/").is_none());
    }

    #[test]
    fn parse_known_git_host_rejects_ambiguous_or_unsafe_identity() {
        for url in [
            "http://github.com/owner/repo",
            "https://user@github.com/owner/repo",
            "https://github.com:444/owner/repo",
            "https://github.com/owner/repo?raw=/other",
            "https://github.com/owner/repo/extra",
            "https://github.com/owner%2Frewrite/repo",
            "https://github.com/owner/%2E%2E/repo",
            "https://github.com.evil.invalid/owner/repo",
            "https://gitlab.com/group/project/-/raw/HEAD/subdir",
            "https://gitlab.com/group/-.git",
            "https://gitlab.com/group/-%2Egit",
        ] {
            assert!(
                parse_known_git_host(url).is_none(),
                "unsafe repository identity must be rejected: {url}"
            );
        }
    }

    #[test]
    fn manifest_names_package_npm_matches_quoted_name() {
        let text = r#"{ "name": "react", "version": "1.0.0" }"#;
        assert!(manifest_names_package(text, "react", Ecosystem::Npm));
        assert!(!manifest_names_package(text, "vue", Ecosystem::Npm));
    }

    #[test]
    fn manifest_names_package_cargo_matches_unquoted_name() {
        let text = "[package]\nname = \"serde\"\nversion = \"1.0.0\"\n";
        assert!(manifest_names_package(text, "serde", Ecosystem::Crates));
        assert!(!manifest_names_package(text, "tokio", Ecosystem::Crates));
    }

    #[test]
    fn verify_returns_unverifiable_for_non_known_host() {
        // No network request — the host parse fails first.
        let v = verify("https://example.com/owner/repo", Ecosystem::Npm, "p");
        assert!(matches!(v.state, RepoMismatchState::Unverifiable));
        assert!(v.reason.contains("does not parse"));
    }

    #[test]
    fn verify_returns_unverifiable_for_unsupported_ecosystem() {
        // No manifest filename for Docker — Unverifiable, not a panic.
        let v = verify(
            "https://github.com/owner/repo",
            Ecosystem::Docker,
            "owner/repo",
        );
        assert!(matches!(v.state, RepoMismatchState::Unverifiable));
    }
}
