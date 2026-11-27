//! Encrypted operation envelopes.
//!
//! Each op is sealed under a DEK-derived subkey with the op id as associated
//! data, so an envelope cannot be relabelled as a different op. Transport only
//! ever carries these envelopes; the plaintext op never leaves the process.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::{self, CTX_OPS, Key, NONCE_LEN};
use crate::model::Op;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireOp {
    pub id: Uuid,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

pub fn seal_op(dek: &Key, op: &Op) -> Result<WireOp> {
    let key = dek.derive(CTX_OPS);
    let nonce: [u8; NONCE_LEN] = crypto::random_bytes();
    let mut plaintext = Vec::new();
    ciborium::into_writer(op, &mut plaintext).context("cannot encode op")?;
    let ciphertext = crypto::seal(&key, &nonce, op.id.as_bytes(), &plaintext)?;
    Ok(WireOp {
        id: op.id,
        nonce,
        ciphertext,
    })
}

pub fn open_op(dek: &Key, wire: &WireOp) -> Result<Op> {
    let key = dek.derive(CTX_OPS);
    let plaintext = crypto::open(&key, &wire.nonce, wire.id.as_bytes(), &wire.ciphertext)
        .context("cannot decrypt op envelope")?;
    let op: Op = ciborium::from_reader(plaintext.as_slice()).context("cannot decode op")?;
    if op.id != wire.id {
        bail!("op envelope id does not match its payload");
    }
    Ok(op)
}

#[cfg(test)]
#[path = "../tests/sync/wire.rs"]
mod tests;
