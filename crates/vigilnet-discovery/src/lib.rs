//! VigilNet Discovery
//!
//! Peer discovery using multiple mechanisms:
//! - Kademlia DHT for global discovery with caching and prefetch
//! - mDNS for local network discovery
//! - Gossip for overlay state propagation
//! - Combined behaviour for libp2p integration
//! - Sybil defense via Proof of Work and reputation

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
    pub fn new() -> Self {
        Self {
            dht: None,
            mdns: None,
            gossip: None,
        }
    }

    pub fn with_dht(mut self, dht: DhtDiscovery) -> Self {
        self.dht = Some(dht);
        self
    }

    pub fn with_mdns(mut self, mdns: MdnsDiscovery) -> Self {
        self.mdns = Some(mdns);
        self
    }

    pub fn with_gossip(mut self, gossip: GossipProtocol) -> Self {
        self.gossip = Some(gossip);
        self
    }

    pub fn start_all(&mut self) -> Result<(), DiscoveryError> {
        if let Some(dht) = &mut self.dht {
            dht.start()?;
        }
        if let Some(mdns) = &mut self.mdns {
            mdns.start()?;
        }
        if let Some(gossip) = &mut self.gossip {
            gossip.start()?;
        }
        Ok(())
    }

    pub fn stop_all(&mut self) -> Result<(), DiscoveryError> {
        if let Some(dht) = &mut self.dht {
            dht.stop()?;
        }
        if let Some(mdns) = &mut self.mdns {
            mdns.stop()?;
        }
        if let Some(gossip) = &mut self.gossip {
            gossip.stop()?;
        }
        Ok(())
    }

    pub fn all_peers(&self) -> HashSet<PeerId> {
        let mut peers = HashSet::new();
        
        if let Some(dht) = &self.dht {
            peers.extend(dht.known_peers());
        }
        if let Some(mdns) = &self.mdns {
            peers.extend(mdns.known_peers());
        }
        if let Some(gossip) = &self.gossip {
            peers.extend(gossip.known_peers());
        }
        
        peers
    }

    pub fn dht_mut(&mut self) -> Option<&mut DhtDiscovery> {
        self.dht.as_mut()
    }

    pub fn mdns_mut(&mut self) -> Option<&mut MdnsDiscovery> {
        self.mdns.as_mut()
    }

    pub fn gossip_mut(&mut self) -> Option<&mut GossipProtocol> {
        self.gossip.as_mut()
    }
}

impl Default for CombinedDiscovery {
    fn default() -> Self {
        Self::new()
    }
}
