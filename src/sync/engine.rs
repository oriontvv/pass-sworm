//! Exchange logic, independent of any transport.
//!
//! One round is enough: the initiator sends every op it has plus the ids it
//! already knows, the responder absorbs them and replies with whatever the
//! initiator is missing. Both sides then hold the union of both logs, because
//! applying an op is idempotent and the merge is commutative.

use std::collections::HashSet;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::Key;
use crate::model::Vault;

use super::wire::{WireOp, open_op, seal_op};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SyncRequest {
    /// Op ids the sender already has, so the peer can skip them.
    pub have: Vec<Uuid>,
    /// The sender's whole log (envelopes are idempotent on the receiving side).
    pub ops: Vec<WireOp>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SyncReply {
    pub ops: Vec<WireOp>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AbsorbReport {
    pub applied: usize,
    pub rejected: usize,
}

/// Decrypt and merge incoming envelopes. A malformed envelope is counted and
/// skipped rather than aborting the whole sync.
pub fn absorb(vault: &mut Vault, dek: &Key, incoming: &[WireOp]) -> AbsorbReport {
    let mut report = AbsorbReport::default();
    for wire in incoming {
        match open_op(dek, wire) {
            Ok(op) => {
                if vault.apply(&op) {
                    report.applied += 1;
                }
            }
            Err(_) => report.rejected += 1,
        }
    }
    report
}

pub fn build_request(vault: &Vault, dek: &Key) -> Result<SyncRequest> {
    let have = vault.oplog.iter().map(|op| op.id).collect();
    let ops = vault
        .oplog
        .iter()
        .map(|op| seal_op(dek, op))
        .collect::<Result<Vec<_>>>()?;
    Ok(SyncRequest { have, ops })
}

pub fn handle_request(
    vault: &mut Vault,
    dek: &Key,
    request: &SyncRequest,
) -> Result<(SyncReply, AbsorbReport)> {
    let report = absorb(vault, dek, &request.ops);
    let have: HashSet<Uuid> = request.have.iter().copied().collect();
    let ops = vault
        .oplog
        .iter()
        .filter(|op| !have.contains(&op.id))
        .map(|op| seal_op(dek, op))
        .collect::<Result<Vec<_>>>()?;
    Ok((SyncReply { ops }, report))
}

#[cfg(test)]
#[path = "../tests/sync/engine.rs"]
mod tests;
