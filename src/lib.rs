//! pass-sworm: a TUI password manager with an encrypted vault.
//!
//! Layer boundaries:
//! - [`crypto`] knows nothing about the vault contents;
//! - [`model`] knows nothing about encryption or the network;
//! - [`format`] ties the model to bytes on disk;
//! - [`store`] only moves bytes and never sees plaintext;
//! - the TUI (in the binary crate) is the only layer that touches secrets.

#![forbid(unsafe_code)]

pub mod config;
pub mod crypto;
pub mod device;
pub mod format;
pub mod generator;
pub mod model;
pub mod store;
pub mod sync;
pub mod timefmt;
