//! Persistent storage: an exclusive lock, atomic saves and rolling backups.

use anyhow::{Context, Result, bail};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

const FILE_MODE: u32 = 0o600;
const DIR_MODE: u32 = 0o700;

/// Paths locked by this process.
///
/// `flock` only guarantees mutual exclusion between processes; whether a
/// second open of the same file *in the same process* conflicts is
/// platform-dependent. An in-process registry makes that case deterministic
/// and also protects against a future background sync task opening the vault
/// a second time.
fn locked_paths() -> &'static Mutex<HashSet<PathBuf>> {
    static LOCKED: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    LOCKED.get_or_init(|| Mutex::new(HashSet::new()))
}

fn registry_key(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

/// Handle to a vault file. Holding it keeps an advisory lock on
/// `<vault>.lock`, so two instances cannot silently clobber each other.
pub struct VaultStore {
    path: PathBuf,
    // Dropping the lock file releases the flock.
    _lock: File,
}

impl VaultStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty()
        {
            create_private_dir(dir)?;
        }

        let lock_path = with_suffix(&path, ".lock");
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .mode(FILE_MODE)
            .open(&lock_path)
            .with_context(|| format!("cannot open lock file {}", lock_path.display()))?;

        let key = registry_key(&path);
        let mut locked = locked_paths().lock().expect("lock registry poisoned");
        if locked.contains(&key) {
            bail!("vault {} is already open in this process", path.display());
        }
        if let Err(e) = lock.try_lock() {
            return Err(anyhow::Error::new(e).context(format!(
                "vault {} is already open in another instance",
                path.display()
            )));
        }
        locked.insert(key);

        Ok(Self { path, _lock: lock })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn read(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        File::open(&self.path)
            .with_context(|| format!("cannot open vault {}", self.path.display()))?
            .read_to_end(&mut buf)
            .with_context(|| format!("cannot read vault {}", self.path.display()))?;
        Ok(buf)
    }

    /// Write the vault atomically: temp file -> fsync -> rename -> fsync dir.
    /// Also rotates up to `keep_backups` previous versions.
    pub fn write(&self, bytes: &[u8], keep_backups: usize) -> Result<()> {
        if self.path.exists() && keep_backups > 0 {
            self.rotate_backups(keep_backups)?;
        }

        let tmp = with_suffix(&self.path, ".tmp");
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(FILE_MODE)
                .open(&tmp)
                .with_context(|| format!("cannot create {}", tmp.display()))?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)
            .with_context(|| format!("cannot replace vault {}", self.path.display()))?;

        if let Some(dir) = self.path.parent()
            && let Ok(d) = File::open(dir)
        {
            let _ = d.sync_all();
        }
        Ok(())
    }

    fn backup_path(&self, n: usize) -> PathBuf {
        with_suffix(&self.path, &format!(".bak.{n}"))
    }

    fn rotate_backups(&self, keep: usize) -> Result<()> {
        for n in (1..keep).rev() {
            let from = self.backup_path(n);
            if from.exists() {
                let _ = fs::rename(&from, self.backup_path(n + 1));
            }
        }
        let first = self.backup_path(1);
        fs::copy(&self.path, &first)
            .with_context(|| format!("cannot back up vault to {}", first.display()))?;
        fs::set_permissions(&first, fs::Permissions::from_mode(FILE_MODE))?;
        Ok(())
    }
}

/// `<path><suffix>` — appends instead of replacing the extension, so
/// `vault.psw` becomes `vault.psw.bak.1`, not `vault.bak.1`.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

impl Drop for VaultStore {
    fn drop(&mut self) {
        let key = registry_key(&self.path);
        if let Ok(mut locked) = locked_paths().lock() {
            locked.remove(&key);
        }
    }
}

fn create_private_dir(dir: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(dir)
        .with_context(|| format!("cannot create directory {}", dir.display()))?;
    // If the directory already existed, only enforce ownership-friendly mode
    // when it is our own private directory.
    if let Ok(meta) = fs::metadata(dir)
        && meta.is_dir()
        && meta.permissions().mode() & 0o077 != 0
    {
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(DIR_MODE));
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/store.rs"]
mod tests;
