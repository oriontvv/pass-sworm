//! Configuration file (`config.toml`).

use crate::crypto::KdfParams;
use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub general: General,
    pub clipboard: ClipboardConfig,
    pub crypto: CryptoCfg,
    pub generator: GeneratorConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct General {
    /// Path to the vault. Empty means "default data directory".
    pub vault: String,
    /// Lock the vault after this many minutes without input. 0 disables it.
    pub auto_lock_minutes: u64,
    /// Number of rotated backups kept next to the vault.
    pub backups: usize,
}

impl Default for General {
    fn default() -> Self {
        Self {
            vault: String::new(),
            auto_lock_minutes: 10,
            backups: 5,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ClipboardConfig {
    /// Seconds before the copied password is wiped. 0 disables the wipe.
    pub clear_after_seconds: u64,
}

impl Default for ClipboardConfig {
    fn default() -> Self {
        Self {
            clear_after_seconds: 30,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CryptoCfg {
    /// Defaults for *new* vaults. Existing vaults keep the parameters stored
    /// in their header.
    pub argon2_m_cost_kib: u32,
    pub argon2_t_cost: u32,
    pub argon2_p_cost: u32,
}

impl Default for CryptoCfg {
    fn default() -> Self {
        let d = KdfParams::default();
        Self {
            argon2_m_cost_kib: d.m_cost_kib,
            argon2_t_cost: d.t_cost,
            argon2_p_cost: d.p_cost,
        }
    }
}

impl CryptoCfg {
    pub fn kdf_params(&self) -> KdfParams {
        KdfParams {
            m_cost_kib: self.argon2_m_cost_kib,
            t_cost: self.argon2_t_cost,
            p_cost: self.argon2_p_cost,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct GeneratorConfig {
    pub length: usize,
    pub symbols: bool,
    /// Exclude visually ambiguous characters (Il1O0).
    pub avoid_ambiguous: bool,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self {
            length: 20,
            symbols: true,
            avoid_ambiguous: true,
        }
    }
}

impl Config {
    /// Load config from `path`, or from the default location when `path` is
    /// `None`. A missing file is not an error: defaults are used.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let path = match path {
            Some(p) => p.to_path_buf(),
            None => match default_config_path() {
                Some(p) => p,
                None => return Ok(Self::default()),
            },
        };
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = fs::read_to_string(&path)
            .with_context(|| format!("cannot read config {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("cannot parse config {}", path.display()))
    }

    /// Resolve the vault path from the config, falling back to the platform
    /// data directory.
    pub fn vault_path(&self) -> Result<PathBuf> {
        if self.general.vault.trim().is_empty() {
            let dirs = project_dirs().context("cannot determine the data directory")?;
            Ok(dirs.data_dir().join("vault.psw"))
        } else {
            Ok(expand_home(&self.general.vault))
        }
    }
}

pub fn default_config_path() -> Option<PathBuf> {
    project_dirs().map(|d| d.config_dir().join("config.toml"))
}

fn project_dirs() -> Option<ProjectDirs> {
    ProjectDirs::from("dev", "pass-sworm", "pass-sworm")
}

pub fn expand_home(raw: &str) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(raw)
}

#[cfg(test)]
#[path = "tests/config.rs"]
mod tests;
