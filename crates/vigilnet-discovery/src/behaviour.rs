//! Combined libp2p network behaviour with E2EE
//!
//! Combines Kademlia DHT, mDNS, Identify, and Gossipsub into a single behaviour.
//! All peer communication is end-to-end encrypted.

use libp2p::{
    gossipsub, identify, kad,
    mdns, noise, tcp, yamux,
    swarm::NetworkBehaviour,
    PeerId, Multiaddr,
};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tracing::{debug, info, warn};
use vigilnet_crypto::{decrypt, encrypt};

use crate::sybil_defense::{ProofOfWork, RateLimiter, ReputationManager};

pub struct E2EESessionManager {
    local_peer_id: PeerId,
    session_keys: HashMap<PeerId, [u8; 32]>,
    local_identity_key: [u8; 32],
    local_session_key: [u8; 32],
    pending_sessions: HashMap<PeerId, ([u8; 32], std::time::Instant)>,
}

impl E2EESessionManager {
    pub fn new(local_peer_id: PeerId, identity_key: [u8; 32], session_key: [u8; 32]) -> Self {
        Self {
            local_peer_id,
            session_keys: HashMap::new(),
            local_identity_key: identity_key,
            local_session_key: session_key,
            pending_sessions: HashMap::new(),
        }
    }

    pub fn set_peer_key(&mut self, peer_id: PeerId, key: [u8; 32]) {
        debug!("E2EE: Established session with peer {} ({:.4})", peer_id, &key[..4]);
        self.session_keys.insert(peer_id, key);
        self.pending_sessions.remove(&peer_id);
    }

    pub fn get_peer_key(&self, peer_id: &PeerId) -> Option<[u8; 32]> {
        self.session_keys.get(peer_id).copied()
    }

    pub fn has_session(&self, peer_id: &PeerId) -> bool {
        self.session_keys.contains_key(peer_id)
    }

    pub fn encrypt(&self, peer_id: &PeerId, plaintext: &[u8]) -> Option<Vec<u8>> {
        let key = self.session_keys.get(peer_id)?;
        encrypt(key, plaintext).ok()
    }

    pub fn decrypt(&self, peer_id: &PeerId, data: &[u8]) -> Option<Vec<u8>> {
        let key = self.session_keys.get(peer_id)?;
        decrypt(key, data).ok()
    }

    pub fn encrypt_broadcast(&self, plaintext: &[u8]) -> Option<Vec<u8>> {
        encrypt(&self.local_session_key, plaintext).ok()
    }

    pub fn decrypt_broadcast(&self, data: &[u8]) -> Option<Vec<u8>> {
        decrypt(&self.local_session_key, data).ok()
    }

    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    pub fn identity_key(&self) -> [u8; 32] {
        self.local_identity_key
    }

    pub fn session_key(&self) -> [u8; 32] {
        self.local_session_key
    }

    pub fn verified_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.session_keys.keys()
    }

    pub fn initiate_session(&mut self, peer_id: PeerId, their_public_key: [u8; 32]) {
        self.pending_sessions.insert(peer_id, (their_public_key, std::time::Instant::now()));
    }

    pub fn get_pending_session(&self, peer_id: &PeerId) -> Option<[u8; 32]> {
        self.pending_sessions.get(peer_id).map(|(key, _)| *key)
    }

    pub fn cleanup_stale_sessions(&mut self, timeout: Duration) {
        let now = std::time::Instant::now();
        self.pending_sessions.retain(|_, (_, time)| now.duration_since(*time) < timeout);
    }
}

#[derive(NetworkBehaviour)]
pub struct VigilNetBehaviour {
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub mdns: mdns::tokio::Behaviour,
    pub identify: identify::Behaviour,
    pub gossipsub: gossipsub::Behaviour,
    pub circuit: libp2p::request_response::Behaviour<vigilnet_routing::protocol::CircuitCodec>,
}

impl VigilNetBehaviour {
    pub fn new(local_peer_id: PeerId, local_key: &libp2p::identity::Keypair) -> Self {
        let store = kad::store::MemoryStore::new(local_peer_id);
        let mut kad_config = kad::Config::default();
        kad_config.set_protocol_names(vec![
            libp2p::StreamProtocol::new("/vigilnet/kad/1.0.0")
        ]);
        kad_config.set_replication_factor(5);
        kad_config.set_record_ttl(Duration::from_secs(3600));
        
        let kademlia = kad::Behaviour::with_config(local_peer_id, store, kad_config);

        let mdns = mdns::tokio::Behaviour::new(
            mdns::Config::default(),
            local_peer_id,
        ).expect("Failed to create mDNS behaviour");

        let identify = identify::Behaviour::new(
            identify::Config::new(
                "/vigilnet/id/1.0.0".to_string(),
                local_key.public(),
            )
            .with_agent_version(format!("vigilnet/{}", env!("CARGO_PKG_VERSION"))),
        );

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(10))
            .heartbeat_initial_delay(Duration::from_secs(5))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .message_id_fn(gossipsub::MessageId::from)
            .max_transmit_size(1024 * 1024)
            .build()
            .expect("Valid gossipsub config");

        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        ).expect("Failed to create gossipsub behaviour");

        let circuit = libp2p::request_response::Behaviour::new(
            std::marker::PhantomData::<vigilnet_routing::protocol::CircuitCodec>,
            std::iter::once((
                vigilnet_routing::protocol::CircuitProtocol,
                libp2p::request_response::ProtocolSupport::Full,
            )),
            libp2p::request_response::Config::default(),
        );

        Self {
            kademlia,
            mdns,
            identify,
            gossipsub,
            circuit,
        }
    }

    pub fn add_address(&mut self, peer_id: &PeerId, addr: Multiaddr) {
        let pow = ProofOfWork::default();
        if !pow.verify(peer_id) {
            info!("Rejected peer {} due to insufficient Proof of Work", peer_id);
            return;
        }

        self.kademlia.add_address(peer_id, addr.clone());
        info!("Added peer {} at {}", peer_id, addr);
    }

    pub fn add_address_with_verification(&mut self, peer_id: &PeerId, addr: Multiaddr, reputation: &ReputationManager) -> bool {
        if !reputation.is_allowed(peer_id) {
            warn!("Rejected peer {} due to low reputation", peer_id);
            return false;
        }

        let pow = ProofOfWork::default();
        if !pow.verify(peer_id) {
            info!("Rejected peer {} due to insufficient Proof of Work", peer_id);
            return false;
        }

        self.kademlia.add_address(peer_id, addr.clone());
        info!("Added verified peer {} at {}", peer_id, addr);
        true
    }

    pub fn bootstrap(&mut self) -> Result<kad::QueryId, String> {
        self.kademlia
            .bootstrap()
            .map_err(|e| format!("Bootstrap failed: {:?}", e))
    }

    pub fn get_closest_peers(&mut self, key: &kad::RecordKey) -> Vec<PeerId> {
        self.kademlia.get_closest_peers(key.clone())
    }

    pub fn subscribe(&mut self, topic: &str) -> Result<bool, gossipsub::SubscriptionError> {
        let topic = gossipsub::IdentTopic::new(topic);
        self.gossipsub.subscribe(&topic)
    }

    pub fn publish(
        &mut self,
        topic: &str,
        data: Vec<u8>,
    ) -> Result<gossipsub::MessageId, gossipsub::PublishError> {
        let topic = gossipsub::IdentTopic::new(topic);
        self.gossipsub.publish(topic, data)
    }

    pub fn publish_encrypted(
        &mut self,
        topic: &str,
        session_manager: &E2EESessionManager,
        plaintext: &[u8],
    ) -> Result<gossipsub::MessageId, gossipsub::PublishError> {
        let encrypted = match session_manager.encrypt_broadcast(plaintext) {
            Some(data) => data,
            None => {
                warn!("Failed to encrypt broadcast message");
                return Err(gossipsub::PublishError::TransformFailed);
            }
        };

        let topic = gossipsub::IdentTopic::new(topic);
        self.gossipsub.publish(topic, encrypted)
    }

    pub fn publish_to_peer(
        &mut self,
        topic: &str,
        peer_id: &PeerId,
        session_manager: &E2EESessionManager,
        plaintext: &[u8],
    ) -> Result<gossipsub::MessageId, gossipsub::PublishError> {
        let encrypted = match session_manager.encrypt(peer_id, plaintext) {
            Some(data) => data,
            None => {
                warn!("Failed to encrypt message for peer {}", peer_id);
                return Err(gossipsub::PublishError::TransformFailed);
            }
        };

        let topic = gossipsub::IdentTopic::new(topic);
        self.gossipsub.publish(topic, encrypted)
    }

    pub fn put_record(&mut self, record: kad::Record) -> Result<kad::QueryId, String> {
        self.kademlia
            .put_record(record, kad::Quorum::One)
            .map_err(|e| format!("Put record failed: {:?}", e))
    }

    pub fn get_record(&mut self, key: &kad::RecordKey) -> Result<kad::QueryId, String> {
        self.kademlia
            .get_record(key.clone(), kad::Quorum::One)
            .map_err(|e| format!("Get record failed: {:?}", e))
    }

    pub fn start_providing(&mut self, key: &kad::RecordKey) -> Result<kad::QueryId, String> {
        self.kademlia
            .start_providing(key.clone())
            .map_err(|e| format!("Start providing failed: {:?}", e))
    }

    pub fn stop_providing(&mut self, key: &kad::RecordKey) {
        self.kademlia.stop_providing(key);
    }

    pub fn get_providers(&mut self, key: &kad::RecordKey) -> Vec<PeerId> {
        self.kademlia.get_providers(key.clone()).collect()
    }
}

#[derive(Debug)]
pub enum VigilNetEvent {
    KademliaPeerDiscovered(PeerId),
    KademliaRoutingUpdated { peer: PeerId, addresses: Vec<Multiaddr> },
    KademliaQueryResult { key: kad::RecordKey, providers: Vec<PeerId> },
    MdnsPeerDiscovered(PeerId, Vec<Multiaddr>),
    MdnsPeerExpired(PeerId),
    IdentifyReceived { peer_id: PeerId, info: identify::Info },
    GossipMessage { 
        peer_id: PeerId, 
        topic: String, 
        data: Vec<u8> 
    },
    GossipMessageDecrypted {
        peer_id: PeerId,
        topic: String,
        plaintext: Vec<u8>,
    },
    GossipSubscribed { peer_id: PeerId, topic: String },
    CircuitMessage {
        peer_id: PeerId,
        message: Vec<u8>,
        channel: libp2p::request_response::ResponseChannel<Vec<u8>>,
    },
    CircuitResponse {
        request_id: libp2p::request_response::RequestId,
        message: Vec<u8>,
    },
    SessionEstablished(PeerId),
    SessionVerifyFailed(PeerId),
}

pub fn map_behaviour_event(
    event: VigilNetBehaviourEvent,
    session_manager: Option<&E2EESessionManager>,
) -> Option<VigilNetEvent> {
    match event {
        VigilNetBehaviourEvent::Mdns(mdns::Event::Discovered(list)) => {
            for (peer_id, addr) in list {
                debug!("mDNS discovered: {} at {}", peer_id, addr);
                return Some(VigilNetEvent::MdnsPeerDiscovered(
                    peer_id,
                    vec![addr],
                ));
            }
            None
        }
        VigilNetBehaviourEvent::Mdns(mdns::Event::Expired(list)) => {
            for (peer_id, _) in list {
                debug!("mDNS expired: {}", peer_id);
                return Some(VigilNetEvent::MdnsPeerExpired(peer_id));
            }
            None
        }
        VigilNetBehaviourEvent::Kademlia(kad::Event::RoutingUpdated { peer, addresses, .. }) => {
            debug!("Kademlia routing updated: {} with {} addresses", peer, addresses.len());
            Some(VigilNetEvent::KademliaRoutingUpdated { 
                peer, 
                addresses: addresses.into_iter().collect() 
            })
        }
        VigilNetBehaviourEvent::Kademlia(kad::Event::PeerDiscovered { peer, .. }) => {
            debug!("Kademlia peer discovered: {}", peer);
            Some(VigilNetEvent::KademliaPeerDiscovered(peer))
        }
        VigilNetBehaviourEvent::Kademlia(kad::Event::QueryResult { 
            result: kad::QueryResult::GetProviders(providers), 
            ..
        }) => {
            let provider_list: Vec<PeerId> = providers.into_iter().collect();
            let key = kad::RecordKey::from(vec![]);
            Some(VigilNetEvent::KademliaQueryResult { 
                key, 
                providers: provider_list 
            })
        }
        VigilNetBehaviourEvent::Identify(identify::Event::Received { peer_id, info }) => {
            debug!("Identify received from {}: {:?}", peer_id, info.protocol_version);
            Some(VigilNetEvent::IdentifyReceived { peer_id, info })
        }
        VigilNetBehaviourEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source,
            message,
            ..
        }) => {
            if let Some(sm) = session_manager {
                if let Some(plaintext) = sm.decrypt(&propagation_source, &message.data) {
                    return Some(VigilNetEvent::GossipMessageDecrypted {
                        peer_id: propagation_source,
                        topic: message.topic.to_string(),
                        plaintext,
                    });
                }
                
                if let Ok(plaintext) = String::from_utf8(message.data.clone()) {
                    debug!("Gossip message (unencrypted) from {}: {}", propagation_source, plaintext);
                }
            }
            
            Some(VigilNetEvent::GossipMessage {
                peer_id: propagation_source,
                topic: message.topic.to_string(),
                data: message.data,
            })
        }
        VigilNetBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic }) => {
            Some(VigilNetEvent::GossipSubscribed { 
                peer_id, 
                topic: topic.to_string() 
            })
        }
        VigilNetBehaviourEvent::Circuit(libp2p::request_response::Event::Message {
            peer,
            message,
        }) => match message {
            libp2p::request_response::Message::Request {
                request,
                channel,
                ..
            } => Some(VigilNetEvent::CircuitMessage {
                peer_id: peer,
                message: request,
                response_channel: channel,
            }),
            libp2p::request_response::Message::Response {
                request_id,
                response,
            } => Some(VigilNetEvent::CircuitResponse {
                request_id,
                message: response,
            }),
        },
        _ => None,
    }
}

pub type VigilNetBehaviourEvent = <VigilNetBehaviour as NetworkBehaviour>::ToSwarm;
