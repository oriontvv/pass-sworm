//! On-disk vault container format.
//!
//! ```text
//! offset  size  field
//!      0     4  magic "PSSW"
//!      4     2  format version (u16 LE)
//!      6     1  kdf id (1 = argon2id)
//!      7     1  flags (reserved, must be 0)
//!      8    16  salt
//!     24     4  m_cost (KiB, u32 LE)
//!     28     4  t_cost
//!     32     4  p_cost
//!     36     4  reserved (must be 0)
//!     40    24  key nonce
//!     64    48  wrapped DEK (32 + 16 tag)
//!    112    24  body nonce
//!    136   ...  body = AEAD(cbor(Vault))
//! ```
//!
//! Two different AADs bind the header to the ciphertexts:
//! - wrapped DEK is sealed with AAD = bytes `0..64`, i.e. the KDF parameters
//!   plus the key nonce. Downgrading `m_cost` or swapping the salt breaks the
//!   unwrap.
//! - the body is sealed with AAD = the full 136-byte header, so the wrapped
//!   DEK and the body nonce are bound to the payload as well.

use crate::crypto::{self, CTX_ENTRIES, KEY_LEN, KdfParams, Key, NONCE_LEN, SALT_LEN, TAG_LEN};
use crate::model::{SCHEMA_VERSION, Vault};
use anyhow::{Context, Result, bail};
use zeroize::Zeroize;

pub const MAGIC: [u8; 4] = *b"PSSW";
pub const FORMAT_VERSION: u16 = 1;
pub const KDF_ARGON2ID: u8 = 1;

const OFF_VERSION: usize = 4;
const OFF_KDF_ID: usize = 6;
const OFF_FLAGS: usize = 7;
const OFF_SALT: usize = 8;
const OFF_M_COST: usize = 24;
const OFF_T_COST: usize = 28;
const OFF_P_COST: usize = 32;
const OFF_RESERVED: usize = 36;
const OFF_KEY_NONCE: usize = 40;
const OFF_WRAPPED_DEK: usize = 64;
const OFF_BODY_NONCE: usize = 112;

/// AAD length for the wrapped DEK: everything before it in the header.
pub const KEY_AAD_LEN: usize = OFF_WRAPPED_DEK;
pub const WRAPPED_DEK_LEN: usize = KEY_LEN + TAG_LEN;
pub const HEADER_LEN: usize = OFF_BODY_NONCE + NONCE_LEN;

#[derive(Debug, Clone)]
pub struct Header {
    pub kdf: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub key_nonce: [u8; NONCE_LEN],
    pub wrapped_dek: [u8; WRAPPED_DEK_LEN],
    pub body_nonce: [u8; NONCE_LEN],
}

impl Header {
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&MAGIC);
        out[OFF_VERSION..OFF_VERSION + 2].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        out[OFF_KDF_ID] = KDF_ARGON2ID;
        out[OFF_FLAGS] = 0;
        out[OFF_SALT..OFF_SALT + SALT_LEN].copy_from_slice(&self.salt);
        out[OFF_M_COST..OFF_M_COST + 4].copy_from_slice(&self.kdf.m_cost_kib.to_le_bytes());
        out[OFF_T_COST..OFF_T_COST + 4].copy_from_slice(&self.kdf.t_cost.to_le_bytes());
        out[OFF_P_COST..OFF_P_COST + 4].copy_from_slice(&self.kdf.p_cost.to_le_bytes());
        out[OFF_RESERVED..OFF_RESERVED + 4].copy_from_slice(&0u32.to_le_bytes());
        out[OFF_KEY_NONCE..OFF_KEY_NONCE + NONCE_LEN].copy_from_slice(&self.key_nonce);
        out[OFF_WRAPPED_DEK..OFF_WRAPPED_DEK + WRAPPED_DEK_LEN].copy_from_slice(&self.wrapped_dek);
        out[OFF_BODY_NONCE..OFF_BODY_NONCE + NONCE_LEN].copy_from_slice(&self.body_nonce);
        out
    }

    /// Parse and validate a header. Treat the input as untrusted.
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        if raw.len() < HEADER_LEN {
            bail!("vault: file shorter than the header");
        }
        if raw[0..4] != MAGIC {
            bail!("vault: bad magic, not a pass-sworm vault");
        }
        let version = u16::from_le_bytes([raw[OFF_VERSION], raw[OFF_VERSION + 1]]);
        if version > FORMAT_VERSION {
            bail!("vault: format version {version} is newer than supported {FORMAT_VERSION}");
        }
        if raw[OFF_KDF_ID] != KDF_ARGON2ID {
            bail!("vault: unknown kdf id {}", raw[OFF_KDF_ID]);
        }
        if raw[OFF_FLAGS] != 0 {
            bail!("vault: unknown flags {:#04x}", raw[OFF_FLAGS]);
        }
        if raw[OFF_RESERVED..OFF_RESERVED + 4] != [0, 0, 0, 0] {
            bail!("vault: reserved header bytes must be zero");
        }

        let kdf = KdfParams {
            m_cost_kib: u32::from_le_bytes(raw[OFF_M_COST..OFF_M_COST + 4].try_into().unwrap()),
            t_cost: u32::from_le_bytes(raw[OFF_T_COST..OFF_T_COST + 4].try_into().unwrap()),
            p_cost: u32::from_le_bytes(raw[OFF_P_COST..OFF_P_COST + 4].try_into().unwrap()),
        };
        kdf.validate()?;

        Ok(Self {
            kdf,
            salt: raw[OFF_SALT..OFF_SALT + SALT_LEN].try_into().unwrap(),
            key_nonce: raw[OFF_KEY_NONCE..OFF_KEY_NONCE + NONCE_LEN]
                .try_into()
                .unwrap(),
            wrapped_dek: raw[OFF_WRAPPED_DEK..OFF_WRAPPED_DEK + WRAPPED_DEK_LEN]
                .try_into()
                .unwrap(),
            body_nonce: raw[OFF_BODY_NONCE..OFF_BODY_NONCE + NONCE_LEN]
                .try_into()
                .unwrap(),
        })
    }
}

/// A decrypted vault together with the material needed to re-seal it.
pub struct Opened {
    pub vault: Vault,
    /// Long-lived data key. Must stay in memory only while unlocked.
    pub dek: Key,
    pub header: Header,
}

/// Create a brand-new encrypted vault.
pub fn create(vault: Vault, password: &str, kdf: KdfParams) -> Result<(Vec<u8>, Opened)> {
    kdf.validate()?;
    let dek = Key::random();

    let mut header = Header {
        kdf,
        salt: crypto::random_bytes(),
        key_nonce: crypto::random_bytes(),
        wrapped_dek: [0u8; WRAPPED_DEK_LEN],
        body_nonce: crypto::random_bytes(),
    };
    // The KEK must come from the salt that is stored in the header.
    let kek = crypto::derive_kek(password, &header.salt, kdf)?;
    let placeholder = header.to_bytes();
    let wrapped = crypto::seal(
        &kek,
        &header.key_nonce,
        &placeholder[..KEY_AAD_LEN],
        dek.bytes(),
    )?;
    header.wrapped_dek.copy_from_slice(&wrapped);

    let bytes = reseal(&vault, &dek, &header)?;
    Ok((bytes, Opened { vault, dek, header }))
}

/// Decrypt a vault with the master password.
pub fn unlock(bytes: &[u8], password: &str) -> Result<Opened> {
    if bytes.len() < HEADER_LEN + TAG_LEN {
        bail!("vault: file is too short to be a vault");
    }
    let (head, body) = bytes.split_at(HEADER_LEN);
    let header = Header::from_bytes(head)?;

    let kek = crypto::derive_kek(password, &header.salt, header.kdf)?;
    let mut dek_bytes = crypto::open(
        &kek,
        &header.key_nonce,
        &head[..KEY_AAD_LEN],
        &header.wrapped_dek,
    )
    .context("vault: wrong master password or corrupted header")?;
    let mut dek_arr = [0u8; KEY_LEN];
    dek_arr.copy_from_slice(&dek_bytes);
    dek_bytes.zeroize();
    let dek = Key::from_bytes(dek_arr);

    let body_key = dek.derive(CTX_ENTRIES);
    let mut plaintext = crypto::open(&body_key, &header.body_nonce, head, body)
        .context("vault: wrong master password or corrupted body")?;
    let decoded = decode_vault(&plaintext);
    plaintext.zeroize();
    let vault = decoded?;

    if vault.schema > SCHEMA_VERSION {
        bail!(
            "vault: schema {} is newer than supported {SCHEMA_VERSION}",
            vault.schema
        );
    }

    Ok(Opened { vault, dek, header })
}

/// Re-encrypt the vault body with a fresh body nonce, leaving the wrapped DEK
/// untouched. Called on every save; nonce reuse with the same key is the one
/// thing a stream-based AEAD must never see.
pub fn reseal(vault: &Vault, dek: &Key, header: &Header) -> Result<Vec<u8>> {
    let mut header = header.clone();
    header.body_nonce = crypto::random_bytes();
    let header_bytes = header.to_bytes();

    let body_key = dek.derive(CTX_ENTRIES);
    let mut plaintext = encode_vault(vault)?;
    let sealed = crypto::seal(&body_key, &header.body_nonce, &header_bytes, &plaintext);
    plaintext.zeroize();
    let sealed = sealed?;

    let mut out = Vec::with_capacity(HEADER_LEN + sealed.len());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn encode_vault(vault: &Vault) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(vault, &mut out).context("vault: cbor encoding failed")?;
    Ok(out)
}

fn decode_vault(plaintext: &[u8]) -> Result<Vault> {
    ciborium::from_reader(plaintext).context("vault: cbor decoding failed")
}

#[cfg(test)]
#[path = "tests/format.rs"]
mod tests;
