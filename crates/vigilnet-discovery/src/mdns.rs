//! mDNS-based local network discovery

use crate::{Discovery, DiscoveryError};
use libp2p::PeerId;
use libp2p::mdns::tokio::{Behaviour as MdnsBehaviour, Config as MdnsConfig};
use libp2p::Multiaddr;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn, error};
use async_trait::async_trait;
use tokio::sync::mpsc;

const MDNS_TTL_SECS: u64 = 20;
const MDNS_CACHE_SIZE: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub peer_id: [u8; 32],
    pub addresses: Vec<String>,
    pub port: u16,
    pub protocol: String,
    pub version: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    pub peer_id: PeerId,
    pub addresses: Vec<Multiaddr>,
    pub first_seen: Instant,
    pub last_seen: Instant,
}

pub struct MdnsDiscovery {
    peers: HashSet<PeerId>,
    peer_addresses: Arc<RwLock<HashMap<PeerId, Vec<Multiaddr>>>>,
    service_name: String,
    active: bool,
    mdns_behaviour: Option<MdnsBehaviour>,
    event_tx: Option<mpsc::Sender<MdnsEvent>>,
}

#[derive(Debug, Clone)]
pub enum MdnsEvent {
    PeerDiscovered(PeerId, Vec<Multiaddr>),
    PeerExpired(PeerId),
}

impl MdnsDiscovery {
    pub fn new() -> Self {
        Self {
            peers: HashSet::new(),
            peer_addresses: Arc::new(RwLock::new(HashMap::new())),
            service_name: "_vigilnet._udp.local".to_string(),
            active: false,
            mdns_behaviour: None,
            event_tx: None,
        }
    }

    pub fn with_service_name(mut self, name: String) -> Self {
        self.service_name = name;
        self
    }

    pub fn create_behaviour(&self, local_peer_id: PeerId) -> MdnsBehaviour {
        let config = MdnsConfig::default()
            .with_ttl(Duration::from_secs(MDNS_TTL_SECS));
        
        MdnsBehaviour::new(config, local_peer_id)
            .expect("Failed to create mDNS behaviour")
    }

    pub fn set_event_sender(&mut self, tx: mpsc::Sender<MdnsEvent>) {
        self.event_tx = Some(tx);
    }

    pub fn on_discovered(&mut self, peer_id: PeerId, addresses: Vec<Multiaddr>) {
        let now = Instant::now();
        
        {
            let mut addr_map = self.peer_addresses.write();
            addr_map.insert(peer_id, addresses.clone());
        }
        
        let is_new = self.peers.insert(peer_id);
        
        if is_new {
            info!("mDNS: Discovered new local peer {} with {} addresses", peer_id, addresses.len());
            
            if let Some(tx) = &self.event_tx {
                let _ = tx.try_send(MdnsEvent::PeerDiscovered(peer_id, addresses));
            }
        } else {
            debug!("mDNS: Updated addresses for peer {}", peer_id);
        }
    }

    pub fn on_expired(&mut self, peer_id: &PeerId) {
        if self.peers.remove(peer_id) {
            info!("mDNS: Local peer {} expired", peer_id);
            
            {
                let mut addr_map = self.peer_addresses.write();
                addr_map.remove(peer_id);
            }
            
            if let Some(tx) = &self.event_tx {
                let _ = tx.try_send(MdnsEvent::PeerExpired(*peer_id));
            }
        }
    }

    pub fn get_addresses(&self, peer_id: &PeerId) -> Option<Vec<Multiaddr>> {
        let addr_map = self.peer_addresses.read();
        addr_map.get(peer_id).cloned()
    }

    pub fn get_all_addresses(&self) -> HashMap<PeerId, Vec<Multiaddr>> {
        let addr_map = self.peer_addresses.read();
        addr_map.clone()
    }

    pub fn active_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers.iter()
    }
}

impl Default for MdnsDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

impl Discovery for MdnsDiscovery {
    fn known_peers(&self) -> HashSet<PeerId> {
        self.peers.clone()
    }

    fn start(&mut self) -> Result<(), DiscoveryError> {
        info!("Starting mDNS discovery for service: {}", self.service_name);
        self.active = true;
        Ok(())
    }

    fn stop(&mut self) -> Result<(), DiscoveryError> {
        info!("Stopping mDNS discovery");
        self.active = false;
        self.peers.clear();
        self.peer_addresses.write().clear();
        Ok(())
    }
}

pub struct MdnsServiceBuilder {
    service_name: String,
    ttl: Duration,
    cache_size: usize,
}

impl MdnsServiceBuilder {
    pub fn new() -> Self {
        Self {
            service_name: "_vigilnet._udp.local".to_string(),
            ttl: Duration::from_secs(MDNS_TTL_SECS),
            cache_size: MDNS_CACHE_SIZE,
        }
    }

    pub fn with_service_name(mut self, name: impl Into<String>) -> Self {
        self.service_name = name.into();
        self
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn with_cache_size(mut self, size: usize) -> Self {
        self.cache_size = size;
        self
    }

    pub fn build(self) -> MdnsDiscovery {
        MdnsDiscovery {
            peers: HashSet::new(),
            peer_addresses: Arc::new(RwLock::new(HashMap::new())),
            service_name: self.service_name,
            active: false,
            mdns_behaviour: None,
            event_tx: None,
        }
    }
}

impl Default for MdnsServiceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mdns_discovery() {
        let discovery = MdnsDiscovery::new();
        assert!(!discovery.active);
    }

    #[test]
    fn test_service_builder() {
        let builder = MdnsServiceBuilder::new()
            .with_service_name("_test._udp.local")
            .with_ttl(Duration::from_secs(10));
        
        let discovery = builder.build();
        assert_eq!(discovery.service_name, "_test._udp.local");
    }
}
