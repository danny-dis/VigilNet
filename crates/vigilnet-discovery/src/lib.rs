//! VigilNet Discovery
//!
//! Peer discovery using multiple mechanisms:
//! - Kademlia DHT for global discovery with caching and prefetch
//! - mDNS for local network discovery
//! - Gossip for overlay state propagation
//! - Combined behaviour for libp2p integration
//! - Sybil defense via Proof of Work and reputation

use tracing::{debug, error, info, instrument, trace, warn};

pub mod behaviour;
pub mod dht;
pub mod gossip;
pub mod sybil_defense;
pub mod mdns;

pub use behaviour::{VigilNetBehaviour, VigilNetBehaviourEvent, VigilNetEvent, E2EESessionManager, map_behaviour_event};
pub use dht::DhtDiscovery;
pub use gossip::GossipProtocol;
pub use mdns::MdnsDiscovery;

use libp2p::PeerId;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    PeerDiscovered(PeerId),
    PeerLost(PeerId),
    PeerAddressesUpdated { peer: PeerId, addresses: Vec<String> },
    VerifiedPeer(PeerId),
    UnverifiedPeer(PeerId),
}

pub trait Discovery: Send + Sync {
    fn known_peers(&self) -> HashSet<PeerId>;
    fn start(&mut self) -> Result<(), DiscoveryError>;
    fn stop(&mut self) -> Result<(), DiscoveryError>;
}

#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("DHT error: {0}")]
    DhtError(String),

    #[error("mDNS error: {0}")]
    MdnsError(String),

    #[error("Gossip error: {0}")]
    GossipError(String),

    #[error("Transport error: {0}")]
    TransportError(String),

    #[error("Sybil defense error: {0}")]
    SybilError(String),
}

pub struct CombinedDiscovery {
    dht: Option<DhtDiscovery>,
    mdns: Option<MdnsDiscovery>,
    gossip: Option<GossipProtocol>,
}

impl CombinedDiscovery {
    #[instrument(level = "debug")]
    pub fn new() -> Self {
        debug!("Creating new CombinedDiscovery");
        Self {
            dht: None,
            mdns: None,
            gossip: None,
        }
    }

    #[instrument(skip(self, dht), level = "debug")]
    pub fn with_dht(mut self, dht: DhtDiscovery) -> Self {
        debug!("Adding DHT discovery");
        self.dht = Some(dht);
        self
    }

    #[instrument(skip(self, mdns), level = "debug")]
    pub fn with_mdns(mut self, mdns: MdnsDiscovery) -> Self {
        debug!("Adding mDNS discovery");
        self.mdns = Some(mdns);
        self
    }

    #[instrument(skip(self, gossip), level = "debug")]
    pub fn with_gossip(mut self, gossip: GossipProtocol) -> Self {
        debug!("Adding Gossip discovery");
        self.gossip = Some(gossip);
        self
    }

    #[instrument(skip(self), level = "info")]
    pub fn start_all(&mut self) -> Result<(), DiscoveryError> {
        info!("Starting all discovery mechanisms");

        if let Some(dht) = &mut self.dht {
            trace!("Starting DHT discovery");
            dht.start()?;
        } else {
            trace!("DHT discovery not configured");
        }

        if let Some(mdns) = &mut self.mdns {
            trace!("Starting mDNS discovery");
            mdns.start()?;
        } else {
            trace!("mDNS discovery not configured");
        }

        if let Some(gossip) = &mut self.gossip {
            trace!("Starting Gossip discovery");
            gossip.start()?;
        } else {
            trace!("Gossip discovery not configured");
        }

        info!("All discovery mechanisms started");
        Ok(())
    }

    #[instrument(skip(self), level = "info")]
    pub fn stop_all(&mut self) -> Result<(), DiscoveryError> {
        info!("Stopping all discovery mechanisms");

        if let Some(dht) = &mut self.dht {
            trace!("Stopping DHT discovery");
            dht.stop()?;
        }

        if let Some(mdns) = &mut self.mdns {
            trace!("Stopping mDNS discovery");
            mdns.stop()?;
        }

        if let Some(gossip) = &mut self.gossip {
            trace!("Stopping Gossip discovery");
            gossip.stop()?;
        }

        info!("All discovery mechanisms stopped");
        Ok(())
    }

    #[instrument(skip(self), level = "debug")]
    pub fn all_peers(&self) -> HashSet<PeerId> {
        let mut peers = HashSet::new();

        if let Some(dht) = &self.dht {
            let dht_peers = dht.known_peers();
            trace!(count = dht_peers.len(), "Adding DHT peers");
            peers.extend(dht_peers);
        }

        if let Some(mdns) = &self.mdns {
            let mdns_peers = mdns.known_peers();
            trace!(count = mdns_peers.len(), "Adding mDNS peers");
            peers.extend(mdns_peers);
        }

        if let Some(gossip) = &self.gossip {
            let gossip_peers = gossip.known_peers();
            trace!(count = gossip_peers.len(), "Adding Gossip peers");
            peers.extend(gossip_peers);
        }

        debug!(total_peers = peers.len(), "Retrieved all peers from discovery");
        peers
    }

    #[instrument(skip(self), level = "trace")]
    pub fn dht_mut(&mut self) -> Option<&mut DhtDiscovery> {
        trace!(has_dht = self.dht.is_some(), "Retrieving DHT discovery");
        self.dht.as_mut()
    }

    #[instrument(skip(self), level = "trace")]
    pub fn mdns_mut(&mut self) -> Option<&mut MdnsDiscovery> {
        trace!(has_mdns = self.mdns.is_some(), "Retrieving mDNS discovery");
        self.mdns.as_mut()
    }

    #[instrument(skip(self), level = "trace")]
    pub fn gossip_mut(&mut self) -> Option<&mut GossipProtocol> {
        trace!(has_gossip = self.gossip.is_some(), "Retrieving Gossip discovery");
        self.gossip.as_mut()
    }
}

impl Default for CombinedDiscovery {
    fn default() -> Self {
        Self::new()
    }
}
