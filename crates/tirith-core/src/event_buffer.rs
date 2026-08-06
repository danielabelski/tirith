//! Cross-event correlation over a bounded, per-session ring of typed events.
//!
//! This module is PURE: it performs no I/O, reads no clock of its own, and
//! touches no global state. Callers (see [`crate::session_warnings`]) own the
//! buffer's persistence and pass the current time in explicitly. That keeps the
//! correlation logic trivially testable and keeps it OFF the hot path: confirmed
//! executions are persisted after caller completion, while pre-execution checks
//! correlate a provisional current event without recording it.
//!
//! The correlations here are "A THEN B within a window" patterns: behaviours
//! that are individually unremarkable but, in sequence and close in time, look
//! like an exfiltration or destruction chain. Each rule maps to a dedicated
//! [`RuleId`] variant flagged `EXTERNALLY_TRIGGERED_RULES` (session/post-process,
//! no PATTERN_TABLE entry).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::verdict::{RuleId, Severity};

/// The class of a recorded event. Deliberately coarse: correlation reasons about
/// "what kind of thing happened", and finer detail lives in
/// [`TypedEvent::metadata`].
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A process/command was executed.
    ProcessExec,
    /// A file was written (created or modified).
    FileWrite,
    /// A file was deleted / unlinked.
    FileDelete,
    /// A `git push --force` (or `-f`) was run.
    GitForcePush,
    /// A network egress (curl/wget/http client, or a network-class rule fired).
    Network,
    /// A secret-bearing file was written (`.env`, `id_rsa`, `.npmrc`, ...).
    SecretWrite,
    /// A pipe-to-shell shape (`curl ... | sh`).
    ShellPipe,
    /// A package install (npm/pip/cargo/brew ...).
    PackageInstall,
}

impl EventKind {
    /// Stable serialized spelling used in durable identities. Keep this explicit:
    /// Rust's `Debug` output is not a persistence format.
    fn stable_tag(self) -> &'static str {
        match self {
            Self::ProcessExec => "process_exec",
            Self::FileWrite => "file_write",
            Self::FileDelete => "file_delete",
            Self::GitForcePush => "git_force_push",
            Self::Network => "network",
            Self::SecretWrite => "secret_write",
            Self::ShellPipe => "shell_pipe",
            Self::PackageInstall => "package_install",
        }
    }
}

/// Assurance attached to a typed event's execution boundary.
///
/// Legacy events default to `Unresolved` because the old JSON recorder carried
/// no execution proof. Strict execution records explicitly mark kernel/gateway
/// completions as `Confirmed`, while the current command
/// is `Provisional` until a trusted boundary durably promotes it. Correlation
/// enforcement may use all three conservatively, but its text must not turn an
/// unresolved observation into an assertion that code ran.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum EventProvenance {
    Confirmed,
    #[default]
    Unresolved,
    Provisional,
}

/// One recorded, time-stamped event. `path` / `host` / `domain` and any other
/// detail live in [`Self::metadata`] so the struct stays stable as new
/// correlations want new context.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TypedEvent {
    /// Stable opaque identity. Empty only while deserializing a legacy event;
    /// session migration fills it deterministically before the event is used.
    #[serde(default)]
    pub event_id: String,
    /// Monotonic sequence within the owning session. Zero is the legacy sentinel
    /// and is replaced under the session lock during migration.
    #[serde(default)]
    pub sequence: u64,
    /// Execution assurance. Missing on legacy records means unresolved because
    /// those records predate the proof-carrying split.
    #[serde(default)]
    pub provenance: EventProvenance,
    /// RFC 3339 UTC timestamp (`chrono::Utc::now().to_rfc3339()`), lexically
    /// comparable against other events recorded the same way.
    pub timestamp: String,
    /// The class of event.
    pub kind: EventKind,
    /// The rule id (or command-derived label) that produced this event.
    pub rule_id: String,
    /// Free-form context: `path`, `host`, `domain`, a `manifest` flag, etc.
    pub metadata: BTreeMap<String, String>,
}

impl TypedEvent {
    /// Convenience constructor used by recorders and tests.
    pub fn new(timestamp: &str, kind: EventKind, rule_id: &str) -> Self {
        Self {
            event_id: String::new(),
            sequence: 0,
            provenance: EventProvenance::Confirmed,
            timestamp: timestamp.to_string(),
            kind,
            rule_id: rule_id.to_string(),
            metadata: BTreeMap::new(),
        }
    }

    /// Builder-style metadata insert.
    pub fn with_meta(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    /// Upgrade a deserialized legacy event to a stable identity. The caller
    /// supplies a unique sequence allocated under the session lock, making
    /// migration deterministic even when two legacy events otherwise have equal
    /// content. The allocator must start above every non-zero legacy/new sequence.
    pub(crate) fn migrate_legacy_identity(&mut self, session_id: &str, assigned_sequence: u64) {
        if self.sequence == 0 {
            self.sequence = assigned_sequence.max(1);
        }
        if self.event_id.is_empty() {
            let mut digest = Sha256::new();
            digest.update(b"tirith-legacy-event-v1\0");
            digest.update(session_id.as_bytes());
            digest.update(b"\0");
            digest.update(self.sequence.to_le_bytes());
            digest.update(b"\0");
            digest.update(self.timestamp.as_bytes());
            digest.update(b"\0");
            digest.update(self.kind.stable_tag().as_bytes());
            digest.update(b"\0");
            digest.update(self.rule_id.as_bytes());
            for (key, value) in &self.metadata {
                digest.update(b"\0");
                digest.update(key.as_bytes());
                digest.update(b"=");
                digest.update(value.as_bytes());
            }
            self.event_id = format!("legacy-{:x}", digest.finalize());
        }
    }

    /// Borrow the `path` metadatum, if present.
    fn path(&self) -> Option<&str> {
        self.metadata.get("path").map(|s| s.as_str())
    }

    /// How many deleted PATHS this [`EventKind::FileDelete`] event represents.
    /// Reads the [`DELETE_COUNT_KEY`] metadatum, defaulting to 1 when absent or
    /// unparsable (back-compat with single-path deletes and pre-existing events).
    fn delete_count(&self) -> usize {
        self.metadata
            .get(DELETE_COUNT_KEY)
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|n| *n >= 1)
            .unwrap_or(1)
    }

    /// How many of this delete event's paths are NON-build-artifacts, for the
    /// mass-deletion correlation (which must not count `dist/`, `node_modules/`,
    /// etc.).
    ///
    /// PREFERS the precomputed [`NON_BUILD_DELETE_COUNT_KEY`] metadatum, which the
    /// deriver fills in by classifying EVERY path in the command individually. That
    /// is the correct value for a MIXED command (`rm app.rs dist/x dist/y` -> 1),
    /// which a single representative path cannot capture.
    ///
    /// FALLS BACK (events recorded before this key existed, or test-constructed
    /// events) to the old single-representative-path heuristic: if the one recorded
    /// `path` is a build artifact, the whole event contributes 0; otherwise it
    /// contributes its [`delete_count`](Self::delete_count). An event with no path
    /// is counted conservatively (cannot be proven a build artifact).
    fn non_build_delete_count(&self) -> usize {
        if let Some(n) = self
            .metadata
            .get(NON_BUILD_DELETE_COUNT_KEY)
            .and_then(|v| v.parse::<usize>().ok())
        {
            return n;
        }
        match self.path() {
            Some(p) if crate::util_build_dirs::is_build_artifact_path(p) => 0,
            _ => self.delete_count(),
        }
    }
}

/// Timestamp-free event derived during preparation. It cannot be mistaken for
/// executed history; the execution gate supplies time, stable id, and sequence
/// only while atomically promoting confirmed evidence.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct EventPrototype {
    pub kind: EventKind,
    pub rule_id: String,
    pub metadata: BTreeMap<String, String>,
}

impl EventPrototype {
    pub fn new(kind: EventKind, rule_id: impl Into<String>) -> Self {
        Self {
            kind,
            rule_id: rule_id.into(),
            metadata: BTreeMap::new(),
        }
    }

    pub fn with_meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    pub(crate) fn materialize(
        self,
        event_id: String,
        sequence: u64,
        timestamp: String,
        provenance: EventProvenance,
    ) -> TypedEvent {
        TypedEvent {
            event_id,
            sequence,
            provenance,
            timestamp,
            kind: self.kind,
            rule_id: self.rule_id,
            metadata: self.metadata,
        }
    }
}

/// A correlation that fired. Mirrors the shape of a [`crate::verdict::Finding`]
/// closely enough that a consumer can surface it as one, but stays decoupled so
/// this module never depends on the full finding/evidence machinery.
#[derive(Clone, Debug)]
pub struct CorrelationHit {
    /// The dedicated correlation rule that matched.
    pub rule_id: RuleId,
    /// Severity for the surfaced finding.
    pub severity: Severity,
    /// Short title.
    pub title: String,
    /// Human-readable description of the matched sequence.
    pub description: String,
    /// Strongest uncertainty among the source events. Consumers can enforce a
    /// hit while preserving an honest audit/presentation claim.
    pub provenance: EventProvenance,
    /// Stable signature identifying THIS specific match. New events contribute
    /// their opaque id plus session sequence; legacy events fall back to their
    /// timestamp. A session-level consumer uses it to de-duplicate the same
    /// A-then-B pair while its source events remain live.
    pub signature: String,
}

/// Window, in seconds, for each correlation rule.
const SECRET_THEN_NETWORK_WINDOW_SECS: i64 = 30;
const DEP_CHANGE_THEN_NETWORK_WINDOW_SECS: i64 = 60;
const DELETE_THEN_FORCE_PUSH_WINDOW_SECS: i64 = 60;
const MASS_DELETE_WINDOW_SECS: i64 = 20;
/// How many file deletions inside [`MASS_DELETE_WINDOW_SECS`] constitute a mass
/// deletion.
const MASS_DELETE_THRESHOLD: usize = 3;

/// Metadata key set on a [`EventKind::FileWrite`] event whose target basename is
/// a dependency manifest. Lets the dependency-change correlation distinguish a
/// manifest write from an arbitrary file write without a second event kind.
pub const MANIFEST_FLAG_KEY: &str = "manifest";

/// Metadata key on a [`EventKind::FileDelete`] event carrying how many PATHS that
/// one delete command targeted (`rm a b c` -> "3"). [`mass_file_deletion`] sums
/// this across events so a single multi-path delete is weighed by paths, not by
/// command count. Absent or unparsable -> treated as 1 (back-compat with events
/// recorded before this key existed, and with single-path deletes).
pub const DELETE_COUNT_KEY: &str = "count";

/// Metadata key on a [`EventKind::FileDelete`] event carrying how many of that one
/// delete command's paths are NON-build-artifacts (the deriver classifies each
/// path with `crate::util_build_dirs::is_build_artifact_path`). [`mass_file_deletion`]
/// SUMS this across events rather than re-deriving artifact status from a single
/// representative path, which would misclassify a MIXED command (e.g.
/// `rm app.rs dist/x dist/y` has one non-build path, not three or zero). Absent
/// (older events / test fixtures) -> the consumer falls back to the per-path
/// heuristic; see [`TypedEvent::non_build_delete_count`].
pub const NON_BUILD_DELETE_COUNT_KEY: &str = "non_build_count";

/// Returns true if `basename` (a file's final path component) is a recognised
/// dependency manifest / lockfile. Conservative and exact-match where possible;
/// lockfiles use a small suffix/contains set so `pnpm-lock.yaml`,
/// `package-lock.json`, etc. all match.
pub fn is_dependency_manifest(basename: &str) -> bool {
    const EXACT: &[&str] = &[
        "package.json",
        "cargo.toml",
        "requirements.txt",
        "go.mod",
        "go.sum",
        "gemfile",
        "pipfile",
        "pyproject.toml",
        "build.gradle",
        "pom.xml",
        "composer.json",
        "package-lock.json",
        "yarn.lock",
        "cargo.lock",
        "poetry.lock",
        "pipfile.lock",
        "gemfile.lock",
        "composer.lock",
        // pnpm lockfile (both YAML extensions); matched EXACTLY like the others so
        // a `contains("pnpm-lock")` does not also catch `notes-pnpm-lock-backup.txt`.
        "pnpm-lock.yaml",
        "pnpm-lock.yml",
        "npm-shrinkwrap.json",
    ];
    let lower = basename.to_ascii_lowercase();
    EXACT.contains(&lower.as_str())
}

/// Compute the RFC 3339 cutoff string for `now_rfc3339 - window_secs`. Returns
/// `None` if `now_rfc3339` does not parse; callers then skip that rule (fail
/// safe: a malformed clock string never fabricates a correlation).
fn cutoff(now_rfc3339: &str, window_secs: i64) -> Option<String> {
    let now = chrono::DateTime::parse_from_rfc3339(now_rfc3339).ok()?;
    let cut = now - chrono::Duration::seconds(window_secs);
    // Render in the SAME shape recorders use (`Utc::now().to_rfc3339()`), so the
    // returned string is lexically comparable against event timestamps.
    Some(cut.with_timezone(&chrono::Utc).to_rfc3339())
}

/// True if `ts` (an event timestamp) is within `[cutoff, now]` for `now`'s
/// window. Both `ts` and `cutoff` are RFC 3339 UTC strings produced the same
/// way, so a lexical compare is an instant compare.
fn within_window(ts: &str, cutoff: &str, now_rfc3339: &str) -> bool {
    let (Ok(ts), Ok(cutoff), Ok(_now)) = (
        chrono::DateTime::parse_from_rfc3339(ts),
        chrono::DateTime::parse_from_rfc3339(cutoff),
        chrono::DateTime::parse_from_rfc3339(now_rfc3339),
    ) else {
        return false;
    };
    // Do not let a local-clock rollback erase a durable event whose monotonic
    // sequence still precedes the current command. A valid future wall-clock
    // timestamp therefore remains conservatively live until the clock catches
    // up; only events older than the lower window bound expire.
    ts >= cutoff
}

fn correlation_provenance(events: &[&TypedEvent]) -> EventProvenance {
    if events
        .iter()
        .any(|event| event.provenance == EventProvenance::Provisional)
    {
        EventProvenance::Provisional
    } else if events
        .iter()
        .any(|event| event.provenance == EventProvenance::Unresolved)
    {
        EventProvenance::Unresolved
    } else {
        EventProvenance::Confirmed
    }
}

fn provenance_safe_description(
    provenance: EventProvenance,
    confirmed: String,
    conservative: String,
) -> String {
    match provenance {
        EventProvenance::Confirmed => confirmed,
        EventProvenance::Unresolved | EventProvenance::Provisional => format!(
            "{conservative} At least one source is pending or has unresolved execution evidence; Tirith enforces this conservatively but does not assert that source executed."
        ),
    }
}

/// Run every correlation rule over `events` as of `now_rfc3339` (an RFC 3339 UTC
/// instant). `events` need not be sorted. Returns one [`CorrelationHit`] per rule
/// that matched (a rule fires at most once per call).
pub fn correlate(events: &[TypedEvent], now_rfc3339: &str) -> Vec<CorrelationHit> {
    let mut hits = Vec::new();

    if let Some(hit) = secret_then_network(events, now_rfc3339) {
        hits.push(hit);
    }
    if let Some(hit) = dependency_change_then_network(events, now_rfc3339) {
        hits.push(hit);
    }
    if let Some(hit) = delete_then_force_push(events, now_rfc3339) {
        hits.push(hit);
    }
    if let Some(hit) = mass_file_deletion(events, now_rfc3339) {
        hits.push(hit);
    }

    hits
}

/// Find the earliest event of `kind` within the window, returning the event.
fn earliest_in_window<'a>(
    events: &'a [TypedEvent],
    kind: EventKind,
    cutoff: &str,
    now_rfc3339: &str,
) -> Option<&'a TypedEvent> {
    events
        .iter()
        .filter(|e| e.kind == kind && within_window(&e.timestamp, cutoff, now_rfc3339))
        .min_by(|a, b| event_order(a, b))
}

fn event_order(left: &TypedEvent, right: &TypedEvent) -> std::cmp::Ordering {
    if left.sequence > 0 && right.sequence > 0 {
        left.sequence
            .cmp(&right.sequence)
            .then_with(|| left.event_id.cmp(&right.event_id))
    } else {
        // Mixed/legacy state has no durable order identity, so retain the old
        // wall-clock ordering as a compatibility fallback.
        left.timestamp
            .cmp(&right.timestamp)
            .then_with(|| left.sequence.cmp(&right.sequence))
            .then_with(|| left.event_id.cmp(&right.event_id))
    }
}

/// `B` of kind `b_kind` happened strictly after `after`, within the wall-clock
/// window. Stable non-zero session sequences are authoritative, including when
/// two separate transitions share a timestamp; legacy/mixed events retain the
/// timestamp fallback.
fn any_after<'a>(
    events: &'a [TypedEvent],
    b_kind: EventKind,
    after: &TypedEvent,
    cutoff: &str,
    now_rfc3339: &str,
) -> Option<&'a TypedEvent> {
    // Return the EARLIEST matching B by timestamp, not the first by slice order, so
    // the result is deterministic regardless of how the ring was filled.
    events
        .iter()
        .filter(|e| {
            e.kind == b_kind
                && within_window(&e.timestamp, cutoff, now_rfc3339)
                && event_order(e, after).is_gt()
        })
        .min_by(|a, b| event_order(a, b))
}

/// Stable signature part for one source event. Prefer identity + sequence;
/// timestamp-only events exist solely for mixed-version compatibility.
fn event_signature_part(event: &TypedEvent) -> String {
    if !event.event_id.is_empty() && event.sequence > 0 {
        format!("e:{}:{}", event.event_id, event.sequence)
    } else {
        format!("t:{}", event.timestamp)
    }
}

/// Build a stable de-dup signature for a correlation from its rule and source
/// events.
fn signature(rule_id: RuleId, events: &[&TypedEvent]) -> String {
    let mut sig = format!("{rule_id:?}");
    for event in events {
        sig.push('|');
        sig.push_str(&event_signature_part(event));
    }
    sig
}

/// The `|`-delimited timestamp parts a signature was built from (everything after
/// the leading `{rule_id:?}` segment). Every [`signature`] call site passes ONLY
/// event timestamps as `parts`, so these are exactly the timestamps of the events
/// that triggered the correlation. A session-level consumer uses this to expire a
/// surfaced signature in lockstep with the event window: once NONE of these source
/// timestamps remain among the live typed events, the correlation can never
/// re-derive, so its dedup marker is safe to drop. Returns an empty iterator for a
/// signature with no `|` (defensive; never produced by [`signature`]).
pub fn signature_event_timestamps(sig: &str) -> impl Iterator<Item = &str> {
    sig.split('|').skip(1).filter_map(|part| {
        if let Some(timestamp) = part.strip_prefix("t:") {
            Some(timestamp)
        } else if part.starts_with("e:") {
            None
        } else {
            // Pre-stable-id signature: the part itself was a timestamp.
            Some(part)
        }
    })
}

/// Whether at least one source named by a correlation signature is still in the
/// live event window. Understands current stable-id signatures and legacy
/// timestamp signatures so mixed-version state expires markers correctly.
pub fn signature_references_live_event(sig: &str, events: &[TypedEvent]) -> bool {
    sig.split('|').skip(1).any(|part| {
        if let Some(rest) = part.strip_prefix("e:") {
            let Some((event_id, sequence)) = rest.rsplit_once(':') else {
                return false;
            };
            let Ok(sequence) = sequence.parse::<u64>() else {
                return false;
            };
            events
                .iter()
                .any(|event| event.event_id == event_id && event.sequence == sequence)
        } else {
            let timestamp = part.strip_prefix("t:").unwrap_or(part);
            events.iter().any(|event| event.timestamp == timestamp)
        }
    })
}

/// SecretWrite THEN Network within 30s -> CRITICAL.
fn secret_then_network(events: &[TypedEvent], now_rfc3339: &str) -> Option<CorrelationHit> {
    let cut = cutoff(now_rfc3339, SECRET_THEN_NETWORK_WINDOW_SECS)?;
    let secret = earliest_in_window(events, EventKind::SecretWrite, &cut, now_rfc3339)?;
    let net = any_after(events, EventKind::Network, secret, &cut, now_rfc3339)?;
    let host = net
        .metadata
        .get("host")
        .or_else(|| net.metadata.get("domain"))
        .map(|h| h.as_str())
        .unwrap_or("a network destination");
    let provenance = correlation_provenance(&[secret, net]);
    Some(CorrelationHit {
        rule_id: RuleId::SecretWriteThenNetwork,
        severity: Severity::Critical,
        title: "Secret write followed by network egress".to_string(),
        description: provenance_safe_description(
            provenance,
            format!(
                "A secret-bearing file was written, then a network call to {host} ran within {SECRET_THEN_NETWORK_WINDOW_SECS}s. This is the shape of a credential-exfiltration chain."
            ),
            format!(
                "A secret-write-shaped event was followed by a network-egress observation for {host} within {SECRET_THEN_NETWORK_WINDOW_SECS}s. This is the shape of a credential-exfiltration chain."
            ),
        ),
        provenance,
        signature: signature(RuleId::SecretWriteThenNetwork, &[secret, net]),
    })
}

/// Dependency-manifest FileWrite THEN Network within 60s -> WARN.
fn dependency_change_then_network(
    events: &[TypedEvent],
    now_rfc3339: &str,
) -> Option<CorrelationHit> {
    let cut = cutoff(now_rfc3339, DEP_CHANGE_THEN_NETWORK_WINDOW_SECS)?;
    // A manifest write is a FileWrite carrying the manifest flag, OR (defence in
    // depth) a FileWrite whose path basename is itself a known manifest.
    let manifest_write = events
        .iter()
        .filter(|e| {
            e.kind == EventKind::FileWrite && within_window(&e.timestamp, &cut, now_rfc3339)
        })
        .filter(|e| {
            e.metadata.get(MANIFEST_FLAG_KEY).map(|v| v == "true") == Some(true)
                || e.path()
                    .map(basename)
                    .map(is_dependency_manifest)
                    .unwrap_or(false)
        })
        .min_by(|a, b| event_order(a, b))?;
    let net = any_after(
        events,
        EventKind::Network,
        manifest_write,
        &cut,
        now_rfc3339,
    )?;
    let what = manifest_write
        .path()
        .map(basename)
        .filter(|b| !b.is_empty())
        .unwrap_or("a dependency manifest");
    let host = net
        .metadata
        .get("host")
        .or_else(|| net.metadata.get("domain"))
        .map(|h| h.as_str())
        .unwrap_or("a network destination");
    let provenance = correlation_provenance(&[manifest_write, net]);
    Some(CorrelationHit {
        rule_id: RuleId::DependencyChangeThenNetwork,
        severity: Severity::Medium,
        title: "Dependency manifest change followed by network egress".to_string(),
        description: provenance_safe_description(
            provenance,
            format!(
                "{what} was modified, then a network call to {host} ran within {DEP_CHANGE_THEN_NETWORK_WINDOW_SECS}s. A dependency edit that immediately phones out can indicate a poisoned install step."
            ),
            format!(
                "A {what} modification-shaped event was followed by a network-egress observation for {host} within {DEP_CHANGE_THEN_NETWORK_WINDOW_SECS}s. This can indicate a poisoned install step."
            ),
        ),
        provenance,
        signature: signature(RuleId::DependencyChangeThenNetwork, &[manifest_write, net]),
    })
}

/// FileDelete THEN GitForcePush within 60s -> CRITICAL.
fn delete_then_force_push(events: &[TypedEvent], now_rfc3339: &str) -> Option<CorrelationHit> {
    let cut = cutoff(now_rfc3339, DELETE_THEN_FORCE_PUSH_WINDOW_SECS)?;
    let del = earliest_in_window(events, EventKind::FileDelete, &cut, now_rfc3339)?;
    let push = any_after(events, EventKind::GitForcePush, del, &cut, now_rfc3339)?;
    let provenance = correlation_provenance(&[del, push]);
    Some(CorrelationHit {
        rule_id: RuleId::DeleteThenForcePush,
        severity: Severity::Critical,
        title: "File deletion followed by git force-push".to_string(),
        description: provenance_safe_description(
            provenance,
            format!(
                "A file was deleted, then a `git push --force` ran within {DELETE_THEN_FORCE_PUSH_WINDOW_SECS}s. Deleting then force-pushing can erase history and overwrite a remote branch."
            ),
            format!(
                "A file-deletion-shaped event was followed by a force-push observation within {DELETE_THEN_FORCE_PUSH_WINDOW_SECS}s. This sequence can erase history and overwrite a remote branch."
            ),
        ),
        provenance,
        signature: signature(RuleId::DeleteThenForcePush, &[del, push]),
    })
}

/// >= 3 deleted NON-BUILD PATHS within 20s -> CRITICAL.
///
/// Counts PATHS, not delete COMMANDS, and counts only NON-build-artifact paths.
/// Each [`EventKind::FileDelete`] event reports its non-build path count via
/// [`TypedEvent::non_build_delete_count`] (the precomputed
/// [`NON_BUILD_DELETE_COUNT_KEY`] metadatum when present, else a per-path fallback),
/// and the threshold is checked against the SUM of those counts across every
/// matching event. So a single `rm a b c d` (one event, four non-build paths) trips
/// the rule, three separate single-path source deletes still do, and a mixed
/// `rm app.rs dist/x dist/y` contributes only its one non-build path, no longer
/// letting the single sampled path decide for the whole batch.
fn mass_file_deletion(events: &[TypedEvent], now_rfc3339: &str) -> Option<CorrelationHit> {
    let cut = cutoff(now_rfc3339, MASS_DELETE_WINDOW_SECS)?;
    let matched: Vec<&TypedEvent> = events
        .iter()
        .filter(|e| {
            e.kind == EventKind::FileDelete && within_window(&e.timestamp, &cut, now_rfc3339)
        })
        .collect();
    // Sum NON-BUILD deleted PATHS across the matching events: each event reports its
    // own non-build path count, so a mixed command contributes exactly its real
    // non-build paths rather than all-or-nothing on one representative path.
    let count: usize = matched.iter().map(|e| e.non_build_delete_count()).sum();
    if count >= MASS_DELETE_THRESHOLD {
        // Signature spans the latest CONTRIBUTING delete so a later burst (a
        // genuinely new mass deletion) re-surfaces while the same set does not.
        // Only deletes that actually contribute a non-build path are eligible: a
        // zero-contribution artifact-only delete (`rm dist/x`) landing later in the
        // window must NOT change the signature, or it would let the SAME already
        // surfaced non-build burst be re-emitted on a pure artifact-cleanup command.
        let mut contributing: Vec<&TypedEvent> = matched
            .iter()
            .filter(|e| e.non_build_delete_count() > 0)
            .copied()
            .collect();
        contributing.sort_unstable_by(|left, right| event_order(left, right));
        let provenance = correlation_provenance(&contributing);
        Some(CorrelationHit {
            rule_id: RuleId::MassFileDeletion,
            severity: Severity::Critical,
            title: "Mass file deletion in a short window".to_string(),
            description: provenance_safe_description(
                provenance,
                format!(
                    "{count} non-build files were deleted within {MASS_DELETE_WINDOW_SECS}s. A burst of deletions can be destructive (ransomware-like or an accidental recursive wipe)."
                ),
                format!(
                    "{count} non-build file-deletion observations fell within {MASS_DELETE_WINDOW_SECS}s. This burst has a destructive shape (ransomware-like or an accidental recursive wipe)."
                ),
            ),
            provenance,
            signature: signature(
                RuleId::MassFileDeletion,
                &[contributing.last().copied()?],
            ),
        })
    } else {
        None
    }
}

/// Final path component, split on both `/` and `\`.
fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `base + offset_secs`, rendered the way recorders render timestamps.
    fn ts(base: chrono::DateTime<chrono::Utc>, offset_secs: i64) -> String {
        (base + chrono::Duration::seconds(offset_secs)).to_rfc3339()
    }

    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }

    fn ev(timestamp: String, kind: EventKind) -> TypedEvent {
        TypedEvent {
            event_id: String::new(),
            sequence: 0,
            provenance: EventProvenance::Confirmed,
            timestamp,
            kind,
            rule_id: "test".to_string(),
            metadata: BTreeMap::new(),
        }
    }

    fn ev_path(timestamp: String, kind: EventKind, path: &str) -> TypedEvent {
        let mut e = ev(timestamp, kind);
        e.metadata.insert("path".to_string(), path.to_string());
        e
    }

    fn ev_path_count(timestamp: String, kind: EventKind, path: &str, count: usize) -> TypedEvent {
        let mut e = ev_path(timestamp, kind, path);
        e.metadata
            .insert(DELETE_COUNT_KEY.to_string(), count.to_string());
        e
    }

    /// A FileDelete event carrying BOTH `count` (total paths) and `non_build_count`
    /// (the precomputed non-build paths), as the real deriver records for a mixed
    /// command. `path` is the representative first path (here a build artifact, to
    /// prove the correlation uses non_build_count and NOT the representative path).
    fn ev_mixed_delete(
        timestamp: String,
        path: &str,
        total: usize,
        non_build: usize,
    ) -> TypedEvent {
        let mut e = ev_path_count(timestamp, EventKind::FileDelete, path, total);
        e.metadata.insert(
            NON_BUILD_DELETE_COUNT_KEY.to_string(),
            non_build.to_string(),
        );
        e
    }

    fn fired(hits: &[CorrelationHit], rule: RuleId) -> bool {
        hits.iter().any(|h| h.rule_id == rule)
    }

    // --- SecretWrite THEN Network -------------------------------------------

    #[test]
    fn secret_then_network_fires_in_window() {
        let base = now();
        // Place both events comfortably inside the 30s window, secret first.
        let events = vec![
            ev(ts(base, -20), EventKind::SecretWrite),
            ev(ts(base, -10), EventKind::Network),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(fired(&hits, RuleId::SecretWriteThenNetwork));
    }

    #[test]
    fn secret_then_network_outside_window_does_not_fire() {
        let base = now();
        // Secret is 40s before now: outside the 30s window.
        let events = vec![
            ev(ts(base, -40), EventKind::SecretWrite),
            ev(ts(base, -38), EventKind::Network),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::SecretWriteThenNetwork));
    }

    #[test]
    fn secret_then_network_wrong_order_does_not_fire() {
        let base = now();
        // Network BEFORE the secret write: not the "A then B" sequence.
        let events = vec![
            ev(ts(base, -20), EventKind::Network),
            ev(ts(base, -10), EventKind::SecretWrite),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::SecretWriteThenNetwork));
    }

    #[test]
    fn secret_then_network_same_instant_does_not_fire() {
        // A single command (`curl https://x -o id_rsa`) emits BOTH a SecretWrite
        // and a Network at one shared timestamp. The network call IS the write,
        // not a subsequent exfiltration, so the strict `>` boundary must keep
        // this from firing a Critical credential-exfiltration correlation.
        let base = now();
        let same = ts(base, -10);
        let events = vec![
            ev(same.clone(), EventKind::SecretWrite),
            ev(same, EventKind::Network),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::SecretWriteThenNetwork));
    }

    // --- DependencyChange THEN Network --------------------------------------

    #[test]
    fn dependency_change_then_network_fires_via_flag() {
        let base = now();
        let mut write = ev(ts(base, -50), EventKind::FileWrite);
        write
            .metadata
            .insert(MANIFEST_FLAG_KEY.to_string(), "true".to_string());
        let events = vec![write, ev(ts(base, -10), EventKind::Network)];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(fired(&hits, RuleId::DependencyChangeThenNetwork));
        // It is a WARN-class (Medium) correlation, not CRITICAL.
        let hit = hits
            .iter()
            .find(|h| h.rule_id == RuleId::DependencyChangeThenNetwork)
            .unwrap();
        assert_eq!(hit.severity, Severity::Medium);
    }

    #[test]
    fn dependency_change_then_network_fires_via_basename() {
        let base = now();
        let events = vec![
            ev_path(ts(base, -50), EventKind::FileWrite, "repo/package.json"),
            ev(ts(base, -5), EventKind::Network),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(fired(&hits, RuleId::DependencyChangeThenNetwork));
    }

    #[test]
    fn dependency_change_non_manifest_write_does_not_fire() {
        let base = now();
        let events = vec![
            ev_path(ts(base, -50), EventKind::FileWrite, "src/main.rs"),
            ev(ts(base, -5), EventKind::Network),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::DependencyChangeThenNetwork));
    }

    #[test]
    fn dependency_change_then_network_outside_window_does_not_fire() {
        let base = now();
        // Manifest write 70s ago: outside the 60s window.
        let events = vec![
            ev_path(ts(base, -70), EventKind::FileWrite, "go.mod"),
            ev(ts(base, -65), EventKind::Network),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::DependencyChangeThenNetwork));
    }

    // --- FileDelete THEN GitForcePush ---------------------------------------

    #[test]
    fn delete_then_force_push_fires_in_window() {
        let base = now();
        let events = vec![
            ev(ts(base, -40), EventKind::FileDelete),
            ev(ts(base, -5), EventKind::GitForcePush),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(fired(&hits, RuleId::DeleteThenForcePush));
    }

    #[test]
    fn delete_then_force_push_wrong_order_does_not_fire() {
        let base = now();
        let events = vec![
            ev(ts(base, -40), EventKind::GitForcePush),
            ev(ts(base, -5), EventKind::FileDelete),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::DeleteThenForcePush));
    }

    #[test]
    fn delete_then_force_push_outside_window_does_not_fire() {
        let base = now();
        // Delete 90s ago: outside the 60s window.
        let events = vec![
            ev(ts(base, -90), EventKind::FileDelete),
            ev(ts(base, -80), EventKind::GitForcePush),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::DeleteThenForcePush));
    }

    // --- Mass file deletion --------------------------------------------------

    #[test]
    fn mass_deletion_fires_at_threshold() {
        let base = now();
        let events = vec![
            ev_path(ts(base, -15), EventKind::FileDelete, "src/a.rs"),
            ev_path(ts(base, -10), EventKind::FileDelete, "src/b.rs"),
            ev_path(ts(base, -5), EventKind::FileDelete, "src/c.rs"),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(fired(&hits, RuleId::MassFileDeletion));
    }

    #[test]
    fn mass_deletion_below_threshold_does_not_fire() {
        let base = now();
        let events = vec![
            ev_path(ts(base, -15), EventKind::FileDelete, "src/a.rs"),
            ev_path(ts(base, -5), EventKind::FileDelete, "src/b.rs"),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::MassFileDeletion));
    }

    #[test]
    fn mass_deletion_excludes_build_artifacts() {
        let base = now();
        // Three deletes, but all under build-artifact dirs: must NOT trip.
        let events = vec![
            ev_path(ts(base, -15), EventKind::FileDelete, "node_modules/a.js"),
            ev_path(ts(base, -10), EventKind::FileDelete, "target/debug/b"),
            ev_path(ts(base, -5), EventKind::FileDelete, "dist/c.js"),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::MassFileDeletion));
    }

    #[test]
    fn mass_deletion_mixes_build_and_source_counts_only_source() {
        let base = now();
        // Two build-artifact deletes + two real source deletes = 2 counted: below
        // the threshold of 3, so it must NOT fire.
        let events = vec![
            ev_path(ts(base, -15), EventKind::FileDelete, "node_modules/a.js"),
            ev_path(ts(base, -14), EventKind::FileDelete, "target/b"),
            ev_path(ts(base, -10), EventKind::FileDelete, "src/x.rs"),
            ev_path(ts(base, -5), EventKind::FileDelete, "src/y.rs"),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::MassFileDeletion));

        // Add a third real source delete: now it fires.
        let mut events = events;
        events.push(ev_path(ts(base, -3), EventKind::FileDelete, "src/z.rs"));
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(fired(&hits, RuleId::MassFileDeletion));
    }

    #[test]
    fn mass_deletion_outside_window_does_not_fire() {
        let base = now();
        // All deletes are >20s old.
        let events = vec![
            ev_path(ts(base, -40), EventKind::FileDelete, "src/a.rs"),
            ev_path(ts(base, -35), EventKind::FileDelete, "src/b.rs"),
            ev_path(ts(base, -30), EventKind::FileDelete, "src/c.rs"),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::MassFileDeletion));
    }

    #[test]
    fn mass_deletion_single_multipath_command_fires() {
        // A SINGLE `rm a b c d` records ONE FileDelete event whose count is 4.
        // Counting PATHS (not events) means it trips the >= 3 threshold on its
        // own, which is the whole point of this fix.
        let base = now();
        let events = vec![ev_path_count(
            ts(base, -5),
            EventKind::FileDelete,
            "src/a.rs",
            4,
        )];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(fired(&hits, RuleId::MassFileDeletion));
    }

    #[test]
    fn mass_deletion_single_multipath_below_threshold_does_not_fire() {
        // `rm a b` is one event, count 2: below the threshold of 3.
        let base = now();
        let events = vec![ev_path_count(
            ts(base, -5),
            EventKind::FileDelete,
            "src/a.rs",
            2,
        )];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::MassFileDeletion));
    }

    #[test]
    fn mass_deletion_single_multipath_artifacts_does_not_fire() {
        // `rm dist/x dist/y dist/z` records one event whose first path is a build
        // artifact, so the event is excluded entirely even though its count is 3.
        let base = now();
        let events = vec![ev_path_count(
            ts(base, -5),
            EventKind::FileDelete,
            "dist/x",
            3,
        )];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::MassFileDeletion));
    }

    #[test]
    fn mass_deletion_missing_count_key_treated_as_one() {
        // Back-compat: events without the count key weigh 1 each, so three of
        // them still trip the rule (the old behaviour) and two do not.
        let base = now();
        let two = vec![
            ev_path(ts(base, -10), EventKind::FileDelete, "src/a.rs"),
            ev_path(ts(base, -5), EventKind::FileDelete, "src/b.rs"),
        ];
        assert!(!fired(
            &correlate(&two, &base.to_rfc3339()),
            RuleId::MassFileDeletion
        ));
        let mut three = two;
        three.push(ev_path(ts(base, -3), EventKind::FileDelete, "src/c.rs"));
        assert!(fired(
            &correlate(&three, &base.to_rfc3339()),
            RuleId::MassFileDeletion
        ));
    }

    #[test]
    fn mass_deletion_sums_counts_across_events() {
        // Two commands: `rm a b` (count 2) then `rm c` (count 1) = 3 paths total.
        let base = now();
        let events = vec![
            ev_path_count(ts(base, -10), EventKind::FileDelete, "src/a.rs", 2),
            ev_path_count(ts(base, -5), EventKind::FileDelete, "src/c.rs", 1),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(fired(&hits, RuleId::MassFileDeletion));
    }

    #[test]
    fn mass_deletion_prefers_non_build_count_over_representative_path() {
        // A7: when an event carries `non_build_count`, the correlation SUMS that and
        // ignores the representative `path`. A mixed `rm app.rs dist/x dist/y` is
        // count=3 but non_build_count=1, and its representative path here is a build
        // artifact: it must contribute 1, not 3 and not 0.
        let base = now();
        // One mixed event (1 non-build) is below the threshold on its own.
        let one = vec![ev_mixed_delete(ts(base, -5), "dist/x", 3, 1)];
        assert!(
            !fired(
                &correlate(&one, &base.to_rfc3339()),
                RuleId::MassFileDeletion
            ),
            "a single mixed delete with one non-build path must NOT fire"
        );
        // Three such mixed events sum to 3 non-build paths and DO fire, even though
        // every representative path is a build artifact (the old heuristic would
        // have excluded them all and never fired).
        let three = vec![
            ev_mixed_delete(ts(base, -15), "dist/x", 3, 1),
            ev_mixed_delete(ts(base, -10), "node_modules/y", 2, 1),
            ev_mixed_delete(ts(base, -5), "target/z", 4, 1),
        ];
        assert!(
            fired(
                &correlate(&three, &base.to_rfc3339()),
                RuleId::MassFileDeletion
            ),
            "three mixed deletes summing to 3 non-build paths must fire"
        );
        // An explicit non_build_count of 0 contributes nothing even with a non-build
        // representative path and a large total count.
        let all_build = vec![ev_mixed_delete(ts(base, -5), "src/keep.rs", 9, 0)];
        assert!(
            !fired(
                &correlate(&all_build, &base.to_rfc3339()),
                RuleId::MassFileDeletion
            ),
            "an explicit non_build_count of 0 must contribute nothing"
        );
    }

    #[test]
    fn mass_deletion_signature_ignores_zero_contribution_deletes() {
        // A zero-contribution artifact-only delete landing LATER in the window must
        // not change the de-dup signature: otherwise the SAME already-surfaced
        // non-build burst would be re-emitted as a fresh hit on a pure artifact
        // cleanup (`rm dist/x`), double-counting it. The signature must span only the
        // latest CONTRIBUTING (non-build) delete.
        let base = now();
        // A real >= 3 non-build burst, with `t-5` the latest contributing delete.
        let burst = vec![
            ev_path(ts(base, -15), EventKind::FileDelete, "src/a.rs"),
            ev_path(ts(base, -10), EventKind::FileDelete, "src/b.rs"),
            ev_path(ts(base, -5), EventKind::FileDelete, "src/c.rs"),
        ];
        let first = correlate(&burst, &base.to_rfc3339());
        let sig_before = first
            .iter()
            .find(|h| h.rule_id == RuleId::MassFileDeletion)
            .expect("the burst must surface MassFileDeletion")
            .signature
            .clone();

        // Now a later pure-artifact `rm dist/x` (0 non-build) enters the window. The
        // burst is unchanged, so the signature must be identical and the
        // session-level dedup would treat it as already surfaced (not re-emitted).
        let mut with_artifact = burst.clone();
        with_artifact.push(ev_path(ts(base, -2), EventKind::FileDelete, "dist/x"));
        let second = correlate(&with_artifact, &base.to_rfc3339());
        let sig_after = second
            .iter()
            .find(|h| h.rule_id == RuleId::MassFileDeletion)
            .expect("the burst still tallies >= 3 non-build paths")
            .signature
            .clone();

        assert_eq!(
            sig_before, sig_after,
            "a zero-contribution artifact delete must not change the signature \
             (would let the same burst re-emit): {sig_before} vs {sig_after}"
        );
        // The signature must anchor on the latest CONTRIBUTING delete (`t-5`), not the
        // later artifact-only delete (`t-2`).
        assert!(
            sig_after.contains(&ts(base, -5)),
            "signature must span the latest non-build delete: {sig_after}"
        );
        assert!(
            !sig_after.contains(&ts(base, -2)),
            "signature must NOT span the zero-contribution artifact delete: {sig_after}"
        );
    }

    #[test]
    fn any_after_returns_earliest_match_regardless_of_slice_order() {
        // A8: with two valid B candidates after A, `any_after` (via the time-ordered
        // correlations) must key on the EARLIEST B by timestamp, deterministically,
        // not the first by slice order. Place the later B first in the slice.
        let base = now();
        let secret_ts = ts(base, -20);
        let early_net = ts(base, -15);
        let late_net = ts(base, -5);
        let events = vec![
            ev(secret_ts.clone(), EventKind::SecretWrite),
            // Later B appears BEFORE the earlier B in slice order.
            ev(late_net.clone(), EventKind::Network),
            ev(early_net.clone(), EventKind::Network),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        let hit = hits
            .iter()
            .find(|h| h.rule_id == RuleId::SecretWriteThenNetwork)
            .expect("secret-then-network must fire");
        // The de-dup signature embeds the chosen B timestamp; it must be the EARLIER
        // network event, independent of slice order.
        assert!(
            hit.signature.contains(&early_net),
            "the earliest matching B must be chosen: {}",
            hit.signature
        );
        assert!(
            !hit.signature.contains(&late_net),
            "the later B must not be the chosen match: {}",
            hit.signature
        );
    }

    #[test]
    fn legacy_missing_provenance_is_unresolved() {
        let event: TypedEvent = serde_json::from_value(serde_json::json!({
            "event_id": "legacy-event",
            "sequence": 1,
            "timestamp": "2026-01-01T00:00:00Z",
            "kind": "network",
            "rule_id": "network_egress",
            "metadata": {}
        }))
        .expect("legacy typed event");
        assert_eq!(event.provenance, EventProvenance::Unresolved);
    }

    #[test]
    fn same_timestamp_events_follow_strict_sequence_order() {
        let base = now();
        let timestamp = base.to_rfc3339();
        let mut secret = ev(timestamp.clone(), EventKind::SecretWrite);
        secret.event_id = "event-secret".to_string();
        secret.sequence = 41;
        let mut network = ev(timestamp, EventKind::Network);
        network.event_id = "event-network".to_string();
        network.sequence = 42;
        let hits = correlate(&[secret, network], &base.to_rfc3339());
        assert!(fired(&hits, RuleId::SecretWriteThenNetwork));
    }

    #[test]
    fn clock_rollback_keeps_durable_prior_event_conservatively_live() {
        let base = now();
        let mut secret = ev(ts(base, 10), EventKind::SecretWrite);
        secret.event_id = "future-secret".to_string();
        secret.sequence = 71;
        let mut network = ev(ts(base, 0), EventKind::Network);
        network.event_id = "current-network".to_string();
        network.sequence = 72;
        let hits = correlate(&[secret, network], &base.to_rfc3339());
        assert!(fired(&hits, RuleId::SecretWriteThenNetwork));
    }

    #[test]
    fn unresolved_correlation_enforces_without_claiming_execution() {
        let base = now();
        let mut secret = ev(ts(base, -10), EventKind::SecretWrite);
        secret.event_id = "unresolved-secret".to_string();
        secret.sequence = 81;
        secret.provenance = EventProvenance::Unresolved;
        let mut network = ev(ts(base, -1), EventKind::Network);
        network.event_id = "confirmed-network".to_string();
        network.sequence = 82;
        let hit = correlate(&[secret, network], &base.to_rfc3339())
            .into_iter()
            .find(|hit| hit.rule_id == RuleId::SecretWriteThenNetwork)
            .expect("conservative correlation");
        assert_eq!(hit.provenance, EventProvenance::Unresolved);
        assert!(hit.description.contains("does not assert"));
        assert!(!hit.description.contains(" ran "));
    }

    // --- helpers + isolation -------------------------------------------------

    #[test]
    fn empty_events_yield_no_hits() {
        let base = now();
        assert!(correlate(&[], &base.to_rfc3339()).is_empty());
    }

    #[test]
    fn malformed_now_is_safe_no_hits() {
        // A clock string that does not parse must never fabricate a correlation.
        let events = vec![
            ev(
                "2026-01-01T00:00:00+00:00".to_string(),
                EventKind::SecretWrite,
            ),
            ev("2026-01-01T00:00:05+00:00".to_string(), EventKind::Network),
        ];
        let hits = correlate(&events, "not-a-timestamp");
        assert!(hits.is_empty());
    }

    #[test]
    fn is_dependency_manifest_matches_known_and_rejects_others() {
        assert!(is_dependency_manifest("package.json"));
        assert!(is_dependency_manifest("Cargo.toml"));
        assert!(is_dependency_manifest("requirements.txt"));
        assert!(is_dependency_manifest("go.mod"));
        assert!(is_dependency_manifest("pnpm-lock.yaml"));
        assert!(is_dependency_manifest("pnpm-lock.yml"));
        assert!(is_dependency_manifest("package-lock.json"));
        assert!(!is_dependency_manifest("main.rs"));
        assert!(!is_dependency_manifest("README.md"));
        // A `contains("pnpm-lock")` would wrongly match a backup-named file; the
        // exact-match family must reject anything but the real lockfile basename.
        assert!(!is_dependency_manifest("notes-pnpm-lock-backup.txt"));
        assert!(!is_dependency_manifest("pnpm-lock.yaml.bak"));
    }

    #[test]
    fn basename_splits_both_separators() {
        assert_eq!(basename("a/b/c.txt"), "c.txt");
        assert_eq!(basename("a\\b\\c.txt"), "c.txt");
        assert_eq!(basename("nodir"), "nodir");
    }
}
