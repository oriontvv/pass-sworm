//! Cryptographic layer: KDF, AEAD and the key hierarchy.
//!
//! ```text
//! master_password --Argon2id(salt,params)--> KEK
//! KEK --XChaCha20Poly1305--> DEK (random, long-lived)
//! DEK --blake3::derive_key(ctx)--> subkeys for the vault body and the op log
//! ```
//!
//! Changing the master password only rewraps the DEK, so ops that are already
//! synced (encrypted under a DEK-derived subkey) stay readable forever.

use anyhow::{Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const SALT_LEN: usize = 16;
pub const TAG_LEN: usize = 16;

pub const DEFAULT_M_COST_KIB: u32 = 64 * 1024;
pub const DEFAULT_T_COST: u32 = 3;
pub const DEFAULT_P_COST: u32 = 4;

/// Subkey derivation contexts. These are part of the on-disk format: do not
/// change them without a format version bump.
pub const CTX_ENTRIES: &str = "pass-sworm/v1/entries";
pub const CTX_OPS: &str = "pass-sworm/v1/ops";
pub const CTX_SYNC_NAMESPACE: &str = "pass-sworm/v1/sync-namespace";

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::fill(&mut out);
    out
}

/// Argon2id parameters are stored in the vault header so that a file can be
/// opened years later even if the built-in defaults change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost_kib: DEFAULT_M_COST_KIB,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }
}

impl KdfParams {
    /// Validate parameters read from an untrusted file. Absurdly large values
    /// are a denial of service (gigabytes of RAM); tiny ones weaken the KDF.
    pub fn validate(&self) -> Result<()> {
        if self.p_cost == 0 || self.p_cost > 64 {
            bail!("kdf: p_cost out of range 1..=64 (got {})", self.p_cost);
        }
        if self.t_cost == 0 || self.t_cost > 64 {
            bail!("kdf: t_cost out of range 1..=64 (got {})", self.t_cost);
        }
        if self.m_cost_kib < 8 * self.p_cost {
            bail!(
                "kdf: m_cost below 8*p_cost ({} < {})",
                self.m_cost_kib,
                8 * self.p_cost
            );
        }
        if self.m_cost_kib > 1024 * 1024 {
            bail!("kdf: m_cost above 1 GiB (got {} KiB)", self.m_cost_kib);
        }
        Ok(())
    }

    fn to_argon2(self) -> Result<Params> {
        Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(KEY_LEN))
            .map_err(|e| anyhow::anyhow!("kdf: invalid argon2id parameters: {e}"))
    }
}

/// 32 bytes of secret material: zeroized on drop, never printed by Debug.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn random() -> Self {
        Self(random_bytes())
    }

    pub fn bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Derive a subkey for a single purpose. `blake3::derive_key` is a real
    /// KDF in derivation mode, so subkeys are independent of each other.
    pub fn derive(&self, context: &str) -> Key {
        Key(blake3::derive_key(context, &self.0))
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

/// Derive a per-session key from the DEK and both handshake nonces.
///
/// `blake3::Hasher::new_keyed` is a PRF, so unique nonces give a fresh session
/// key per connection even though the DEK is long-lived.
pub fn derive_session_key(dek: &Key, context: &str, parts: &[&[u8]]) -> Key {
    let mut hasher = blake3::Hasher::new_keyed(dek.bytes());
    hasher.update(context.as_bytes());
    for part in parts {
        hasher.update(part);
    }
    Key(*hasher.finalize().as_bytes())
}

/// Keyed MAC over a sequence of byte strings.
pub fn keyed_mac(key: &Key, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key.bytes());
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// master password -> KEK. The only place Argon2id runs on user input.
pub fn derive_kek(password: &str, salt: &[u8; SALT_LEN], params: KdfParams) -> Result<Key> {
    params.validate()?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.to_argon2()?);
    let mut out = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow::anyhow!("kdf: argon2id failed: {e}"))?;
    Ok(Key(out))
}

pub fn seal(key: &Key, nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.bytes().into());
    cipher
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("aead: encryption failed"))
}

pub fn open(key: &Key, nonce: &[u8; NONCE_LEN], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.bytes().into());
    cipher
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("aead: wrong key, password or corrupted data"))
}

#[cfg(test)]
#[path = "tests/crypto.rs"]
mod tests;
