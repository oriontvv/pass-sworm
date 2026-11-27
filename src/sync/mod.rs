//! Sync between replicas of the same vault.
//!
//! The unit of exchange is the op log, not the vault snapshot: peers trade
//! operations, and each side merges them with the same rules it uses locally.
//!
//! Layers, bottom to top:
//! - [`wire`]: individually encrypted op envelopes;
//! - [`engine`]: transport-independent exchange (what to send, how to absorb);
//! - [`session`]: handshake and exchange over any async byte stream;
//! - [`node`]: the iroh endpoint. Peers are addressed by endpoint id only.

pub mod engine;
pub mod node;
pub mod session;
pub mod wire;

pub use engine::{AbsorbReport, SyncReply, SyncRequest, absorb, build_request, handle_request};
pub use node::{NetConfig, SYNC_ALPN, SyncNode};
pub use session::SyncOutcome;
pub use wire::{WireOp, open_op, seal_op};
