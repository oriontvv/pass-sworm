//! Per-installation device identity.
//!
//! The replica id must belong to the *installation*, not to the vault file:
//! pairing works by copying the encrypted vault to another machine, and two
//! devices sharing a replica id would produce colliding sequence numbers. So
//! the id lives in a sidecar file next to the vault and is created on first
//! open on each machine.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub replica: Uuid,
    #[serde(default)]
    pub name: String,
    /// Hex-encoded ed25519 secret of the iroh endpoint. Its public half is the
    /// endpoint id, the only address a peer ever needs.
    #[serde(default)]
    pub secret: String,
}

/// Hand-written so the secret can never leak through `{:?}`, a panic message or
/// a log line.
impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("replica", &self.replica)
            .field("name", &self.name)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl DeviceIdentity {
    /// Load the identity for this installation, creating it when absent.
    pub fn load_or_create(vault_path: &Path) -> Result<Self> {
        let path = sidecar_path(vault_path);
        if path.exists() {
            let text = fs::read_to_string(&path)
                .with_context(|| format!("cannot read device file {}", path.display()))?;
            let mut device: Self = toml::from_str(&text)
                .with_context(|| format!("cannot parse device file {}", path.display()))?;
            if device.secret.is_empty() {
                // Device files written before sync existed have no key yet.
                device.secret = new_secret_hex();
                write_private(&path, &device, true)?;
            }
            return Ok(device);
        }

        let device = Self {
            replica: Uuid::now_v7(),
            name: hostname(),
            secret: new_secret_hex(),
        };
        write_private(&path, &device, false)?;
        Ok(device)
    }

    /// The iroh secret key of this installation.
    pub fn secret_key(&self) -> Result<iroh::SecretKey> {
        self.secret
            .parse()
            .map_err(|e| anyhow::anyhow!("device file holds an invalid secret key: {e}"))
    }

    /// Public endpoint id, the only thing a user copies to pair devices.
    pub fn endpoint_id(&self) -> Result<iroh::EndpointId> {
        Ok(self.secret_key()?.public())
    }
}

fn new_secret_hex() -> String {
    let bytes = crate::crypto::random_bytes::<32>();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn write_private(path: &Path, device: &DeviceIdentity, overwrite: bool) -> Result<()> {
    let text = toml::to_string(device).context("cannot encode device file")?;
    let mut options = fs::OpenOptions::new();
    options.write(true).mode(0o600);
    if overwrite {
        options.truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot write device file {}", path.display()))?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

pub fn sidecar_path(vault_path: &Path) -> PathBuf {
    let mut s = vault_path.as_os_str().to_os_string();
    s.push(".device");
    PathBuf::from(s)
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .and_then(|out| String::from_utf8(out.stdout).ok())
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty())
        })
        .unwrap_or_else(|| "device".into())
}

#[cfg(test)]
#[path = "tests/device.rs"]
mod tests;
