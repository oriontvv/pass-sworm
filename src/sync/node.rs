//! The iroh node: identity, discovery and QUIC streams.
//!
//! Peers are addressed by endpoint id only. iroh resolves an id to a way of
//! reaching it through address lookup (DNS/pkarr, mDNS on the LAN, optionally
//! the mainline DHT) and then hole-punches, falling back to a relay. No IP
//! address is ever typed, shown or stored by this program.
//!
//! The published record is filtered to the relay URL only, so the device's IP
//! addresses do not end up in a public DNS zone.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use iroh::address_lookup::{
    AddrFilter, DnsAddressLookup, MemoryLookup, PkarrPublisher, PkarrResolver,
};
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey};
use iroh_mainline_address_lookup::DhtAddressLookup;
use iroh_mdns_address_lookup::MdnsAddressLookup;

use crate::crypto::Key;
use crate::model::Vault;

use super::session::{self, SyncOutcome};

/// ALPN of the sync protocol. Bump the suffix on incompatible changes.
pub const SYNC_ALPN: &[u8] = b"pass-sworm/sync/1";

/// How long the acceptor waits for the initiator to close after the reply, so
/// QUIC does not discard the last bytes when the connection is dropped.
const CLOSE_GRACE: Duration = Duration::from_secs(3);
/// Upper bound for a single inbound session, so a stalled stranger cannot
/// block the accept loop.
const SESSION_LIMIT: Duration = Duration::from_secs(60);
const ONLINE_WAIT: Duration = Duration::from_secs(10);

/// How this node finds and reaches peers.
#[derive(Debug, Clone)]
pub struct NetConfig {
    /// Use the public relays and DNS/pkarr address lookup.
    pub relay: bool,
    /// Discover peers on the local network via mDNS.
    pub mdns: bool,
    /// Publish to and resolve from the mainline DHT.
    pub dht: bool,
    /// Bind to the loopback interface only. For tests and isolated setups.
    pub loopback_only: bool,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            relay: true,
            mdns: true,
            dht: false,
            loopback_only: false,
        }
    }
}

impl NetConfig {
    /// No network discovery at all; addresses must be supplied through
    /// [`SyncNode::remember`]. Used by tests.
    pub fn isolated() -> Self {
        Self {
            relay: false,
            mdns: false,
            dht: false,
            loopback_only: true,
        }
    }
}

pub struct SyncNode {
    endpoint: Endpoint,
    memory: MemoryLookup,
    online: bool,
}

impl SyncNode {
    pub async fn start(secret: SecretKey, net: &NetConfig) -> Result<Self> {
        let memory = MemoryLookup::new();
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(secret)
            .alpns(vec![SYNC_ALPN.to_vec()])
            .address_lookup(memory.clone());

        builder = if net.relay {
            builder
                .relay_mode(RelayMode::Default)
                // Publish the relay URL only: never the device's IP addresses.
                .address_lookup(PkarrPublisher::n0_dns().addr_filter(AddrFilter::relay_only()))
                .address_lookup(PkarrResolver::n0_dns())
                .address_lookup(DnsAddressLookup::n0_dns())
        } else {
            builder.relay_mode(RelayMode::Disabled)
        };
        if net.mdns {
            builder = builder.address_lookup(MdnsAddressLookup::builder());
        }
        if net.dht {
            builder = builder.address_lookup(DhtAddressLookup::builder());
        }
        if net.loopback_only {
            builder = builder
                .bind_addr("127.0.0.1:0")
                .context("cannot bind to the loopback interface")?;
        }

        let endpoint = builder
            .bind()
            .await
            .context("cannot start the iroh endpoint")?;
        Ok(Self {
            endpoint,
            memory,
            online: net.relay,
        })
    }

    /// This node's public identity. The only thing a user ever has to copy.
    pub fn id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// Full addressing information. Only needed for tests and isolated
    /// networks; normal peers are found by id alone.
    pub fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// Provide addressing information out of band. Lets isolated test nodes
    /// find each other without any discovery service.
    pub fn remember(&self, addr: EndpointAddr) {
        self.memory.add_endpoint_info(addr);
    }

    /// Wait until the home relay is reachable, so peers can find this node.
    /// Returns false if that did not happen in time; sync may still work over
    /// the local network.
    pub async fn wait_online(&self) -> bool {
        if !self.online {
            return true;
        }
        tokio::time::timeout(ONLINE_WAIT, self.endpoint.online())
            .await
            .is_ok()
    }

    /// Connect to a peer by endpoint id and exchange op logs.
    pub async fn sync_with(
        &self,
        peer: EndpointId,
        vault: &mut Vault,
        dek: &Key,
        timeout: Duration,
    ) -> Result<SyncOutcome> {
        let work = async {
            let conn = self
                .endpoint
                .connect(peer, SYNC_ALPN)
                .await
                .with_context(|| format!("cannot reach peer {}", peer.fmt_short()))?;

            let result = async {
                let (mut send, mut recv) = conn.open_bi().await.context("cannot open a stream")?;
                let outcome = session::run_client(&mut recv, &mut send, vault, dek).await?;
                let _ = send.finish();
                Ok::<_, anyhow::Error>(outcome)
            }
            .await;

            // Close on every path, including a failed handshake, so the peer's
            // accept loop is released immediately instead of waiting for a stall.
            let code: u8 = if result.is_ok() { 0 } else { 1 };
            conn.close(code.into(), b"done");
            result
        };
        tokio::time::timeout(timeout, work)
            .await
            .context("timed out while syncing")?
    }

    /// Accept peers until one completes a sync. Failed attempts (a stranger,
    /// the wrong vault, a stalled connection) are reported through `on_event`
    /// and do not end the wait.
    pub async fn serve(
        &self,
        vault: &mut Vault,
        dek: &Key,
        timeout: Duration,
        mut on_event: impl FnMut(&str),
    ) -> Result<SyncOutcome> {
        let accept_loop = async {
            loop {
                let Some(incoming) = self.endpoint.accept().await else {
                    bail!("the endpoint was closed");
                };
                let accepting = match incoming.accept() {
                    Ok(accepting) => accepting,
                    Err(err) => {
                        on_event(&format!("ignored a broken connection attempt: {err:#}"));
                        continue;
                    }
                };

                let session = async {
                    let conn = accepting.await.context("connection handshake failed")?;
                    let remote = conn.remote_id();
                    on_event(&format!("peer {} connected", remote.fmt_short()));
                    let (mut send, mut recv) =
                        conn.accept_bi().await.context("peer opened no stream")?;
                    let outcome = session::run_server(&mut recv, &mut send, vault, dek)
                        .await
                        .with_context(|| format!("peer {}", remote.fmt_short()))?;
                    let _ = send.finish();
                    let _ = tokio::time::timeout(CLOSE_GRACE, conn.closed()).await;
                    Ok::<_, anyhow::Error>(outcome)
                };

                match tokio::time::timeout(SESSION_LIMIT, session).await {
                    Ok(Ok(outcome)) => return Ok(outcome),
                    Ok(Err(err)) => on_event(&format!("session failed: {err:#}")),
                    Err(_) => on_event("session timed out"),
                }
            }
        };
        tokio::time::timeout(timeout, accept_loop)
            .await
            .context("timed out waiting for a peer")?
    }

    pub async fn close(self) {
        self.endpoint.close().await;
    }
}

#[cfg(test)]
#[path = "../tests/sync/node.rs"]
mod tests;
