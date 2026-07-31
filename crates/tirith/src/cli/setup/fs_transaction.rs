//! Shared read-modify-write transaction orchestration for setup-managed files.
//!
//! Platform modules provide capability-style parent traversal, snapshots,
//! temporary files, backups, and publication. This module owns the ordering:
//! lock, live snapshot, transform, backup, durable temp, generation check,
//! publication, directory durability, and retention.

use std::path::Path;

use super::fs_helpers::{PlatformSnapshot, PlatformTransaction};

/// Setup files are configuration and hook text, not arbitrary payloads. The
/// cap bounds both the initial snapshot and the mandatory pre-publication
/// generation check. Reads use cap+1 so an exact-limit file remains valid.
pub(crate) const MAX_SETUP_FILE_BYTES: usize = 10 * 1024 * 1024;

/// Immutable live state observed through a no-follow handle.
pub(crate) struct FileSnapshot {
    inner: PlatformSnapshot,
}

impl FileSnapshot {
    pub(crate) fn exists(&self) -> bool {
        self.inner.bytes.is_some()
    }

    pub(crate) fn bytes(&self) -> Option<&[u8]> {
        self.inner.bytes.as_deref()
    }

    pub(crate) fn text(&self, path: &Path) -> Result<Option<&str>, String> {
        self.bytes()
            .map(|bytes| {
                std::str::from_utf8(bytes)
                    .map_err(|error| format!("{} is not valid UTF-8: {error}", path.display()))
            })
            .transpose()
    }

    #[cfg(unix)]
    pub(crate) fn mode(&self) -> Option<u32> {
        self.inner.mode
    }
}

/// A pure transform result. The shared transaction owns all filesystem side
/// effects represented here.
pub(crate) enum FileUpdate {
    Unchanged,
    Write {
        bytes: Vec<u8>,
        mode: u32,
        preserve_existing_mode: bool,
        backup: bool,
    },
}

impl FileUpdate {
    pub(crate) fn unchanged() -> Self {
        Self::Unchanged
    }

    pub(crate) fn write_text(content: String, mode: u32) -> Self {
        Self::Write {
            bytes: content.into_bytes(),
            mode,
            preserve_existing_mode: true,
            backup: false,
        }
    }

    /// Hook scripts must become executable in the same atomic publication,
    /// rather than through a later chmod of the live path.
    #[cfg(unix)]
    pub(crate) fn with_exact_mode(mut self) -> Self {
        if let Self::Write {
            preserve_existing_mode,
            ..
        } = &mut self
        {
            *preserve_existing_mode = false;
        }
        self
    }

    pub(crate) fn with_backup(mut self, backup: bool) -> Self {
        if let Self::Write {
            backup: requested, ..
        } = &mut self
        {
            *requested = backup;
        }
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransactionOutcome {
    Unchanged,
    DryRunWouldWrite,
    Written,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub(crate) enum TestStage {
    TempSynced,
    SnapshotValidated,
    Published,
}

pub(crate) fn transactional_update<F>(
    path: &Path,
    scope_root: &Path,
    dry_run: bool,
    transform: F,
) -> Result<TransactionOutcome, String>
where
    F: FnOnce(&FileSnapshot) -> Result<FileUpdate, String>,
{
    transactional_update_checked(path, scope_root, dry_run, transform, || Ok(()))
}

/// Variant used when selecting the destination itself requires filesystem
/// preflights (for example bash's `.bashrc`/`.bash_profile` fallback). The
/// selection is revalidated after the live snapshot and immediately before
/// the destination generation check.
pub(crate) fn transactional_update_checked<F, V>(
    path: &Path,
    scope_root: &Path,
    dry_run: bool,
    transform: F,
    revalidate_selection: V,
) -> Result<TransactionOutcome, String>
where
    F: FnOnce(&FileSnapshot) -> Result<FileUpdate, String>,
    V: FnMut() -> Result<(), String>,
{
    transactional_update_impl(
        path,
        scope_root,
        dry_run,
        transform,
        revalidate_selection,
        #[cfg(test)]
        |_| Ok(()),
    )
}

fn transactional_update_impl<F, V>(
    path: &Path,
    scope_root: &Path,
    dry_run: bool,
    transform: F,
    mut revalidate_selection: V,
    #[cfg(test)] mut test_hook: impl FnMut(TestStage) -> Result<(), String>,
) -> Result<TransactionOutcome, String>
where
    F: FnOnce(&FileSnapshot) -> Result<FileUpdate, String>,
    V: FnMut() -> Result<(), String>,
{
    if dry_run {
        let snapshot = FileSnapshot {
            inner: super::fs_helpers::read_snapshot_scoped(path, scope_root)?,
        };
        return match transform(&snapshot)? {
            FileUpdate::Unchanged => Ok(TransactionOutcome::Unchanged),
            FileUpdate::Write { .. } => Ok(TransactionOutcome::DryRunWouldWrite),
        };
    }

    // Creating and locking the stable sibling is intentionally restricted to
    // mutating runs. The parent handles and lock live through retention.
    let transaction = PlatformTransaction::begin(path, scope_root)?;
    let snapshot = FileSnapshot {
        inner: transaction.read_snapshot()?,
    };
    let update = transform(&snapshot)?;
    let FileUpdate::Write {
        bytes,
        mode,
        preserve_existing_mode,
        backup,
    } = update
    else {
        return Ok(TransactionOutcome::Unchanged);
    };

    let mut backup_guard = if backup && snapshot.exists() {
        Some(transaction.create_backup(&snapshot.inner)?)
    } else {
        None
    };

    // `TempGuard` is armed before any bytes are written. Every error from this
    // point until publication removes the secret-bearing temporary sibling.
    let temp = transaction.prepare_temp(&bytes, mode, preserve_existing_mode, &snapshot.inner)?;
    #[cfg(test)]
    test_hook(TestStage::TempSynced)?;

    revalidate_selection()?;
    transaction.validate_snapshot(&snapshot.inner)?;
    #[cfg(test)]
    test_hook(TestStage::SnapshotValidated)?;

    transaction.publish(temp, &snapshot.inner)?;
    // Publication completed. A later durability error must retain the backup
    // as recovery material rather than rolling it back.
    if let Some(backup) = backup_guard.as_mut() {
        backup.commit();
    }
    #[cfg(test)]
    test_hook(TestStage::Published)?;
    transaction.sync_parent()?;

    if backup_guard.is_some() {
        if let Err(error) = transaction.cleanup_old_backups(backup_guard.as_ref()) {
            eprintln!("tirith: could not clean old backups: {error}");
        }
    }

    Ok(TransactionOutcome::Written)
}

#[cfg(test)]
pub(crate) fn transactional_update_with_hook<F, H>(
    path: &Path,
    scope_root: &Path,
    transform: F,
    hook: H,
) -> Result<TransactionOutcome, String>
where
    F: FnOnce(&FileSnapshot) -> Result<FileUpdate, String>,
    H: FnMut(TestStage) -> Result<(), String>,
{
    transactional_update_impl(path, scope_root, false, transform, || Ok(()), hook)
}
