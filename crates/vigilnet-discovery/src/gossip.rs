//! Gossipsub-based overlay state propagation with E2EE

use crate::{Discovery, DiscoveryError};
use crate::sybil_defense::{ProofOfWork, RateLimiter, ReputationManager};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use lru::LruCache;
use tracing::{debug, info, warn};
use vigilnet_crypto::{decrypt, encrypt};
use rand::Rng;

const GOSSIP_NONCE_SIZE: usize = 12;
const GOSSIP_TAG_SIZE: usize = 16;
const MESSAGE_CACHE_SIZE: usize = 1000;
const MAX_MESSAGE_AGE_SECS: u64 = 300;
const FANOUT_PEERS: usize = 6;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedGossipPayload {
    pub sender_id: [u8; 32],
    pub nonce: [u8; GOSSIP_NONCE_SIZE],
    pub ciphertext: Vec<u8>,
    pub message_id: [u8; 16],
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipMessage {
    pub msg_type: GossipMessageType,
    pub peer_info: PeerInfo,
    pub message_id: [u8; 16],
    pub ttl: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GossipMessageType {
    PeerAnnounce,
    PeerDepart,
    PeerQuery,
    PeerResponse(Vec<PeerInfo>),
    CircuitState(Vec<u8>),
    Heartbeat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: [u8; 32],
    pub addresses: Vec<String>,
    pub signed_timestamp: u64,
    pub signature: [u8; 64],
    pub proof_of_work: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CachedMessage {
    pub message_id: [u8; 16],
    pub data: Vec<u8>,
    pub received_at: Instant,
    pub peer_count: u32,
}

pub struct GossipProtocol {
    peers: HashSet<PeerId>,
    peer_topic: String,
    circuit_topic: String,
    heartbeat_topic: String,
    session_keys: HashMap<PeerId, [u8; 32]>,
    local_identity: Option<([u8; 32], [u8; 32])>,
    proof_of_work: ProofOfWork,
    message_cache: Arc<RwLock<LruCache<[u8; 16], CachedMessage>>>,
    seen_messages: Arc<RwLock<HashSet<[u8; 16]>>>,
    pending_announces: Arc<RwLock<VecDeque<(Vec<String>, Instant)>>>,
    rate_limiter: Arc<RateLimiter>,
    reputation_manager: Arc<ReputationManager>,
    last_heartbeat: Arc<RwLock<Instant>>,
    last_announce: Arc<RwLock<Instant>>,
    heartbeat_interval: Duration,
    announce_interval: Duration,
}

impl GossipProtocol {
    pub fn new() -> Self {
        Self {
            peers: HashSet::new(),
            peer_topic: "vigilnet/peers/1.0".to_string(),
            circuit_topic: "vigilnet/circuits/1.0".to_string(),
            heartbeat_topic: "vigilnet/heartbeat/1.0".to_string(),
            session_keys: HashMap::new(),
            local_identity: None,
            proof_of_work: ProofOfWork::default(),
            message_cache: Arc::new(RwLock::new(LruCache::new(MESSAGE_CACHE_SIZE))),
            seen_messages: Arc::new(RwLock::new(HashSet::new())),
            pending_announces: Arc::new(RwLock::new(VecDeque::new())),
            rate_limiter: Arc::new(RateLimiter::new(50, 60)),
            reputation_manager: Arc::new(ReputationManager::new(-10.0)),
            last_heartbeat: Arc::new(RwLock::new(Instant::now())),
            last_announce: Arc::new(RwLock::new(Instant::now())),
            heartbeat_interval: Duration::from_secs(30),
            announce_interval: Duration::from_secs(60),
        }
    }

    pub fn with_identity(mut self, peer_id_bytes: [u8; 32], session_key: [u8; 32]) -> Self {
        self.local_identity = Some((peer_id_bytes, session_key));
        self
    }

    pub fn with_rate_limiter(mut self, limiter: RateLimiter) -> Self {
        self.rate_limiter = Arc::new(limiter);
        self
    }

    pub fn with_reputation_manager(mut self, manager: ReputationManager) -> Self {
        self.reputation_manager = Arc::new(manager);
        self
    }

    pub fn peer_topic(&self) -> &str {
        &self.peer_topic
    }

    pub fn circuit_topic(&self) -> &str {
        &self.circuit_topic
    }

    pub fn heartbeat_topic(&self) -> &str {
        &self.heartbeat_topic
    }

    pub fn set_session_key(&mut self, peer_id: PeerId, key: [u8; 32]) {
        debug!("Gossip: Setting session key for peer {}", peer_id);
        self.session_keys.insert(peer_id, key);
    }

    pub fn get_session_key(&self, peer_id: &PeerId) -> Option<[u8; 32]> {
        self.session_keys.get(peer_id).copied()
    }

    pub fn encrypt_for_peer(&self, peer_id: &PeerId, plaintext: &[u8]) -> Option<Vec<u8>> {
        let key = self.session_keys.get(peer_id)?;
        encrypt(key, plaintext).ok()
    }

    pub fn decrypt_from_peer(&self, peer_id: &PeerId, data: &[u8]) -> Option<Vec<u8>> {
        let key = self.session_keys.get(peer_id)?;
        decrypt(key, data).ok()
    }

    pub fn is_message_seen(&self, message_id: &[u8; 16]) -> bool {
        let seen = self.seen_messages.read();
        seen.contains(message_id)
    }

    pub fn mark_message_seen(&self, message_id: [u8; 16]) {
        let mut seen = self.seen_messages.write();
        seen.insert(message_id);
        
        if seen.len() > MESSAGE_CACHE_SIZE * 2 {
            let to_remove: Vec<_> = seen.iter().take(seen.len() / 2).cloned().collect();
            for id in to_remove {
                seen.remove(&id);
            }
        }
    }

    fn generate_message_id() -> [u8; 16] {
        let mut rng = rand::thread_rng();
        let mut id = [0u8; 16];
        rng.fill(&mut id);
        id
    }

    pub fn encrypt_broadcast(&self, message: &GossipMessage) -> Option<EncryptedGossipPayload> {
        let (sender_id, session_key) = self.local_identity.as_ref()?;
        let plaintext = serde_json::to_vec(message).ok()?;
        
        let ciphertext = encrypt(&session_key, &plaintext).ok()?;
        
        if ciphertext.len() < GOSSIP_NONCE_SIZE + GOSSIP_TAG_SIZE {
            warn!("Encrypted payload too short");
            return None;
        }
        
        let nonce = ciphertext[..GOSSIP_NONCE_SIZE].try_into().ok()?;
        let ciphertext_only = ciphertext[GOSSIP_NONCE_SIZE..].to_vec();
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Some(EncryptedGossipPayload {
            sender_id: *sender_id,
            nonce,
            ciphertext: ciphertext_only,
            message_id: message.message_id,
            timestamp,
        })
    }

    pub fn decrypt_broadcast(&self, payload: &EncryptedGossipPayload) -> Option<GossipMessage> {
        let mut full_ciphertext = Vec::with_capacity(GOSSIP_NONCE_SIZE + payload.ciphertext.len());
        full_ciphertext.extend_from_slice(&payload.nonce);
        full_ciphertext.extend_from_slice(&payload.ciphertext);
        
        if let Some((_, local_key)) = &self.local_identity {
            if let Ok(plaintext) = decrypt(local_key, &full_ciphertext) {
                if let Ok(message) = serde_json::from_slice::<GossipMessage>(&plaintext) {
                    return Some(message);
                }
            }
        }
        
        for key in self.session_keys.values() {
            if let Ok(plaintext) = decrypt(key, &full_ciphertext) {
                if let Ok(message) = serde_json::from_slice::<GossipMessage>(&plaintext) {
                    return Some(message);
                }
            }
        }
        
        None
    }

    pub fn on_message(&mut self, topic: &str, data: &[u8], source: &PeerId) -> Option<GossipMessage> {
        if !self.rate_limiter.check_rate_limit(source) {
            debug!("Gossip: Rate limited peer {}", source);
            return None;
        }
        
        if let Ok(payload) = serde_json::from_slice::<EncryptedGossipPayload>(data) {
            if self.is_message_seen(&payload.message_id) {
                return None;
            }
            
            self.mark_message_seen(payload.message_id);
            
            if let Some(plaintext) = self.decrypt_from_sender(&payload) {
                if let Ok(message) = serde_json::from_slice::<GossipMessage>(&plaintext) {
                    {
                        let mut cache = self.message_cache.write();
                        cache.put(payload.message_id, CachedMessage {
                            message_id: payload.message_id,
                            data: data.to_vec(),
                            received_at: Instant::now(),
                            peer_count: 1,
                        });
                    }
                    
                    self.handle_decrypted_message(topic, &message);
                    return Some(message);
                }
            }
        }
        
        if let Ok(message) = serde_json::from_slice::<GossipMessage>(data) {
            self.handle_decrypted_message(topic, &message);
            return Some(message);
        }
        
        None
    }

    fn decrypt_from_sender(&self, payload: &EncryptedGossipPayload) -> Option<Vec<u8>> {
        let mut full_ciphertext = Vec::with_capacity(GOSSIP_NONCE_SIZE + payload.ciphertext.len());
        full_ciphertext.extend_from_slice(&payload.nonce);
        full_ciphertext.extend_from_slice(&payload.ciphertext);
        
        for key in self.session_keys.values() {
            if let Ok(plaintext) = decrypt(key, &full_ciphertext) {
                return Some(plaintext);
            }
        }
        
        None
    }

    fn handle_decrypted_message(&mut self, topic: &str, message: &GossipMessage) {
        match &message.msg_type {
            GossipMessageType::PeerAnnounce => {
                let peer_id = PeerId::from_bytes(&message.peer_info.peer_id).ok();
                if let Some(pid) = peer_id {
                    if !self.proof_of_work.verify(&pid) {
                        warn!("Gossip: Peer {} has insufficient PoW", pid);
                        return;
                    }
                    
                    if self.peers.insert(pid) {
                        info!("Gossip: Discovered peer {}", pid);
                        self.reputation_manager.record_successful_interaction(&pid);
                    }
                }
            }
            GossipMessageType::PeerDepart => {
                let peer_id = PeerId::from_bytes(&message.peer_info.peer_id).ok();
                if let Some(pid) = peer_id {
                    self.peers.remove(&pid);
                    info!("Gossip: Peer departed {}", pid);
                }
            }
            GossipMessageType::PeerQuery => {
                debug!("Gossip: Received peer query on {}", topic);
            }
            GossipMessageType::PeerResponse(peers) => {
                for peer_info in peers {
                    if let Ok(pid) = PeerId::from_bytes(&peer_info.peer_id) {
                        if self.proof_of_work.verify(&pid) {
                            self.peers.insert(pid);
                        }
                    }
                }
            }
            GossipMessageType::CircuitState(state) => {
                debug!("Gossip: Received circuit state ({} bytes)", state.len());
            }
            GossipMessageType::Heartbeat => {
                debug!("Gossip: Received heartbeat on {}", topic);
            }
        }
    }

    pub fn announce_self(&self, addresses: Vec<String>) -> Option<Vec<u8>> {
        let (sender_id, _) = self.local_identity.as_ref()?;
        
        let message = GossipMessage {
            msg_type: GossipMessageType::PeerAnnounce,
            peer_info: PeerInfo {
                peer_id: *sender_id,
                addresses,
                signed_timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                signature: [0u8; 64],
                proof_of_work: vec![],
            },
            message_id: Self::generate_message_id(),
            ttl: 3,
        };
        
        if let Some(encrypted) = self.encrypt_broadcast(&message) {
            serde_json::to_vec(&encrypted).ok()
        } else {
            serde_json::to_vec(&message).ok()
        }
    }

    pub fn create_depart_message(&self) -> Option<Vec<u8>> {
        let (sender_id, _) = self.local_identity.as_ref()?;
        
        let message = GossipMessage {
            msg_type: GossipMessageType::PeerDepart,
            peer_info: PeerInfo {
                peer_id: *sender_id,
                addresses: vec![],
                signed_timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                signature: [0u8; 64],
                proof_of_work: vec![],
            },
            message_id: Self::generate_message_id(),
            ttl: 1,
        };
        
        if let Some(encrypted) = self.encrypt_broadcast(&message) {
            serde_json::to_vec(&encrypted).ok()
        } else {
            serde_json::to_vec(&message).ok()
        }
    }

    pub fn create_peer_query(&self) -> Option<Vec<u8>> {
        let (sender_id, _) = self.local_identity.as_ref()?;
        
        let message = GossipMessage {
            msg_type: GossipMessageType::PeerQuery,
            peer_info: PeerInfo {
                peer_id: *sender_id,
                addresses: vec![],
                signed_timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                signature: [0u8; 64],
                proof_of_work: vec![],
            },
            message_id: Self::generate_message_id(),
            ttl: 2,
        };
        
        if let Some(encrypted) = self.encrypt_broadcast(&message) {
            serde_json::to_vec(&encrypted).ok()
        } else {
            serde_json::to_vec(&message).ok()
        }
    }

    pub fn create_peer_response(&self, peers: Vec<PeerInfo>) -> Option<Vec<u8>> {
        let (sender_id, _) = self.local_identity.as_ref()?;
        
        let message = GossipMessage {
            msg_type: GossipMessageType::PeerResponse(peers),
            peer_info: PeerInfo {
                peer_id: *sender_id,
                addresses: vec![],
                signed_timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                signature: [0u8; 64],
                proof_of_work: vec![],
            },
            message_id: Self::generate_message_id(),
            ttl: 2,
        };
        
        if let Some(encrypted) = self.encrypt_broadcast(&message) {
            serde_json::to_vec(&encrypted).ok()
        } else {
            serde_json::to_vec(&message).ok()
        }
    }

    pub fn create_circuit_state_message(&self, circuit_data: Vec<u8>) -> Option<Vec<u8>> {
        let (sender_id, _) = self.local_identity.as_ref()?;
        
        let message = GossipMessage {
            msg_type: GossipMessageType::CircuitState(circuit_data),
            peer_info: PeerInfo {
                peer_id: *sender_id,
                addresses: vec![],
                signed_timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                signature: [0u8; 64],
                proof_of_work: vec![],
            },
            message_id: Self::generate_message_id(),
            ttl: 2,
        };
        
        if let Some(encrypted) = self.encrypt_broadcast(&message) {
            serde_json::to_vec(&encrypted).ok()
        } else {
            serde_json::to_vec(&message).ok()
        }
    }

    pub fn create_heartbeat(&self) -> Option<Vec<u8>> {
        let (sender_id, _) = self.local_identity.as_ref()?;
        
        let message = GossipMessage {
            msg_type: GossipMessageType::Heartbeat,
            peer_info: PeerInfo {
                peer_id: *sender_id,
                addresses: vec![],
                signed_timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                signature: [0u8; 64],
                proof_of_work: vec![],
            },
            message_id: Self::generate_message_id(),
            ttl: 1,
        };
        
        if let Some(encrypted) = self.encrypt_broadcast(&message) {
            serde_json::to_vec(&encrypted).ok()
        } else {
            serde_json::to_vec(&message).ok()
        }
    }

    pub fn should_announce(&self) -> bool {
        self.last_announce.read().elapsed() >= self.announce_interval
    }

    pub fn should_send_heartbeat(&self) -> bool {
        self.last_heartbeat.read().elapsed() >= self.heartbeat_interval
    }

    pub fn record_announce(&self) {
        *self.last_announce.write() = Instant::now();
    }

    pub fn record_heartbeat(&self) {
        *self.last_heartbeat.write() = Instant::now();
    }

    pub fn get_fanout_peers(&self, count: usize) -> Vec<PeerId> {
        self.reputation_manager.top_peers(count)
    }

    pub fn pending_announce(&self, addresses: Vec<String>) {
        let mut queue = self.pending_announces.write();
        queue.push_back((addresses, Instant::now()));
    }

    pub fn get_pending_announce(&self) -> Option<(Vec<String>, bool)> {
        let mut queue = self.pending_announces.write();
        if let Some((addresses, time)) = queue.pop_front() {
            let should_send = time.elapsed() < Duration::from_secs(5);
            Some((addresses, should_send))
        } else {
            None
        }
    }

    pub fn clean_expired_messages(&self) {
        let mut cache = self.message_cache.write();
        let now = Instant::now();
        
        let keys_to_remove: Vec<_> = cache
            .iter()
            .filter(|(_, msg)| now.duration_since(msg.received_at).as_secs() > MAX_MESSAGE_AGE_SECS)
            .map(|(k, _)| *k)
            .collect();
        
        for key in keys_to_remove {
            cache.remove(&key);
        }
        
        let mut seen = self.seen_messages.write();
        let seen_count = seen.len();
        if seen_count > MESSAGE_CACHE_SIZE * 2 {
            let to_remove: Vec<_> = seen.iter().take(seen_count / 2).cloned().collect();
            for id in to_remove {
                seen.remove(&id);
            }
        }
    }
}

impl Default for GossipProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Discovery for GossipProtocol {
    fn known_peers(&self) -> HashSet<PeerId> {
        self.peers.clone()
    }

    fn start(&mut self) -> Result<(), DiscoveryError> {
        info!("Starting gossip protocol with E2EE");
        Ok(())
    }

    fn stop(&self) -> Result<(), DiscoveryError> {
        info!("Stopping gossip protocol");
        Ok(())
    }
}
