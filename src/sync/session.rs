//! Transport-agnostic sync session over any async byte stream.
//!
//! iroh already authenticates the peer's endpoint id; this layer decides whether
//! that peer belongs to this vault. Both sides derive a session key from the DEK
//! and two fresh nonces and prove knowledge of it with a keyed MAC. All traffic
//! after the handshake is encrypted under the session key.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::crypto::{self, Key, NONCE_LEN, TAG_LEN};
use crate::model::Vault;

use super::engine::{self, SyncReply, SyncRequest};

pub const PROTOCOL_VERSION: u16 = 1;
const MAX_FRAME: usize = 64 * 1024 * 1024;
const FRAME_AAD: &[u8] = b"pass-sworm/frame/v1";
const SESSION_CONTEXT: &str = "pass-sworm/v1/session";
const AUTH_FAILED: &str = "peer failed authentication: different master password or vault";

/// What one sync session moved.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncOutcome {
    /// Ops handed to the peer.
    pub sent: usize,
    /// Ops received from the peer.
    pub received: usize,
    /// Received ops that changed local state.
    pub applied: usize,
    /// Received ops that failed to decrypt or decode.
    pub rejected: usize,
}

impl SyncOutcome {
    pub fn describe(&self) -> String {
        format!(
            "{} sent, {} received, {} applied, {} rejected",
            self.sent, self.received, self.applied, self.rejected
        )
    }
}

#[derive(Serialize, Deserialize)]
struct Hello {
    version: u16,
    nonce: [u8; 32],
    mac: Option<[u8; 32]>,
}

#[derive(Serialize, Deserialize)]
struct Proof {
    mac: [u8; 32],
}

/// Initiator side: send our log, absorb the peer's reply.
pub async fn run_client<R, W>(
    r: &mut R,
    w: &mut W,
    vault: &mut Vault,
    dek: &Key,
) -> Result<SyncOutcome>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let nc: [u8; 32] = crypto::random_bytes();
    send_msg(
        w,
        &Hello {
            version: PROTOCOL_VERSION,
            nonce: nc,
            mac: None,
        },
    )
    .await?;

    let hello: Hello = recv_msg(r).await?;
    check_version(hello.version)?;
    let ns = hello.nonce;
    let session = session_key(dek, &nc, &ns);
    let theirs = hello.mac.context("server sent no proof")?;
    if !same(&mac(&session, b"server-auth", &nc, &ns), &theirs) {
        bail!(AUTH_FAILED);
    }
    send_msg(
        w,
        &Proof {
            mac: mac(&session, b"client-auth", &nc, &ns),
        },
    )
    .await?;

    let request = engine::build_request(vault, dek)?;
    let sent = request.ops.len();
    write_frame(w, &seal(&session, &encode(&request)?)?).await?;

    let reply: SyncReply = decode(&open(&session, &read_frame(r).await?)?)?;
    let report = engine::absorb(vault, dek, &reply.ops);
    Ok(SyncOutcome {
        sent,
        received: reply.ops.len(),
        applied: report.applied,
        rejected: report.rejected,
    })
}

/// Acceptor side: verify the peer, absorb its log, reply with what it lacks.
pub async fn run_server<R, W>(
    r: &mut R,
    w: &mut W,
    vault: &mut Vault,
    dek: &Key,
) -> Result<SyncOutcome>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let hello: Hello = recv_msg(r).await?;
    check_version(hello.version)?;
    let nc = hello.nonce;
    let ns: [u8; 32] = crypto::random_bytes();
    let session = session_key(dek, &nc, &ns);
    send_msg(
        w,
        &Hello {
            version: PROTOCOL_VERSION,
            nonce: ns,
            mac: Some(mac(&session, b"server-auth", &nc, &ns)),
        },
    )
    .await?;

    let proof: Proof = recv_msg(r).await?;
    if !same(&mac(&session, b"client-auth", &nc, &ns), &proof.mac) {
        bail!(AUTH_FAILED);
    }

    let request: SyncRequest = decode(&open(&session, &read_frame(r).await?)?)?;
    let received = request.ops.len();
    let (reply, report) = engine::handle_request(vault, dek, &request)?;
    let sent = reply.ops.len();
    write_frame(w, &seal(&session, &encode(&reply)?)?).await?;
    Ok(SyncOutcome {
        sent,
        received,
        applied: report.applied,
        rejected: report.rejected,
    })
}

fn check_version(version: u16) -> Result<()> {
    if version != PROTOCOL_VERSION {
        bail!("peer speaks protocol v{version}, this build speaks v{PROTOCOL_VERSION}");
    }
    Ok(())
}

fn session_key(dek: &Key, nc: &[u8; 32], ns: &[u8; 32]) -> Key {
    crypto::derive_session_key(dek, SESSION_CONTEXT, &[nc, ns])
}

fn mac(session: &Key, label: &[u8], nc: &[u8; 32], ns: &[u8; 32]) -> [u8; 32] {
    crypto::keyed_mac(session, &[label, nc, ns])
}

fn same(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).unwrap_u8() == 1
}

fn seal(session: &Key, plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce: [u8; NONCE_LEN] = crypto::random_bytes();
    let ciphertext = crypto::seal(session, &nonce, FRAME_AAD, plaintext)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn open(session: &Key, frame: &[u8]) -> Result<Vec<u8>> {
    if frame.len() < NONCE_LEN + TAG_LEN {
        bail!("frame is too short");
    }
    let (nonce, ciphertext) = frame.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("slice of NONCE_LEN bytes");
    crypto::open(session, &nonce, FRAME_AAD, ciphertext)
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_FRAME {
        bail!("frame of {} bytes exceeds the limit", payload.len());
    }
    w.write_all(&(payload.len() as u32).to_be_bytes()).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        bail!("frame of {len} bytes exceeds the limit");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn send_msg<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, msg: &T) -> Result<()> {
    write_frame(w, &encode(msg)?).await
}

async fn recv_msg<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> Result<T> {
    decode(&read_frame(r).await?)
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).context("cannot encode message")?;
    Ok(out)
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ciborium::from_reader(bytes).context("cannot decode message")
}

#[cfg(test)]
#[path = "../tests/sync/session.rs"]
mod tests;
