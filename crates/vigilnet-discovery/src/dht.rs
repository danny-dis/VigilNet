//! Kademlia DHT-based peer discovery with E2EE, caching, and prefetch

use crate::{Discovery, DiscoveryError};
use crate::sybil_defense::{ProofOfWork, RateLimiter, ReputationManager};
use libp2p::kad::{self, store::MemoryStore, Record, RecordKey, KBucketEntry, QueryId, QueryPeer};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH, Duration, Instant};
use parking_lot::RwLock;
use lru::LruCache;
use tracing::{debug, error, info, instrument, trace, warn};
use vigilnet_crypto::{decrypt, encrypt};

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

const DHT_NONCE_SIZE: usize = 12;
const DHT_TAG_SIZE: usize = 16;
const CACHE_SIZE: usize = 1000;
const PREFETCH_COUNT: usize = 5;
const RECORD_TTL_SECS: u64 = 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPeerRecord {
    pub sender_id: [u8; 32],
    pub nonce: [u8; DHT_NONCE_SIZE],
    pub ciphertext: Vec<u8>,
    pub signature: [u8; 64],
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub peer_id: [u8; 32],
    pub addresses: Vec<String>,
    pub session_key: [u8; 32],
    pub timestamp: u64,
    pub version: u32,
    pub proof_of_work: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CachedRecord {
    pub record: Record,
    pub cached_at: Instant,
    pub access_count: u32,
}

pub struct DhtDiscovery {
    local_peer_id: PeerId,
    peers: HashSet<PeerId>,
    bootstrap_peers: Vec<(PeerId, String)>,
    protocol_name: String,
    session_keys: HashMap<PeerId, [u8; 32]>,
    local_identity: Option<([u8; 32], [u8; 32])>,
    verified_peers: HashSet<PeerId>,
    
    record_cache: Arc<RwLock<LruCache<RecordKey, CachedRecord>>>,
    pending_queries: Arc<RwLock<HashSet<QueryId>>>,
    prefetch_queue: Arc<RwLock<VecDeque<RecordKey>>>,
    last_prefetch: Arc<RwLock<Instant>>,
    
    rate_limiter: Arc<RateLimiter>,
    reputation_manager: Arc<ReputationManager>,
    proof_of_work: ProofOfWork,
    
    bootstrap_nodes: Vec<PeerId>,
    routing_table_size: usize,
}

impl DhtDiscovery {
    #[instrument(level = "info")]
    pub fn new(local_peer_id: PeerId) -> Self {
        info!(local_peer_id = %local_peer_id, "Creating new DHT discovery");
        Self {
            local_peer_id,
            peers: HashSet::new(),
            bootstrap_peers: Vec::new(),
            protocol_name: "/vigilnet/kad/1.0.0".to_string(),
            session_keys: HashMap::new(),
            local_identity: None,
            verified_peers: HashSet::new(),
            record_cache: Arc::new(RwLock::new(LruCache::new(CACHE_SIZE))),
            pending_queries: Arc::new(RwLock::new(HashSet::new())),
            prefetch_queue: Arc::new(RwLock::new(VecDeque::new())),
            last_prefetch: Arc::new(RwLock::new(Instant::now())),
            rate_limiter: Arc::new(RateLimiter::new(100, 60)),
            reputation_manager: Arc::new(ReputationManager::new(-10.0)),
            proof_of_work: ProofOfWork::default(),
            bootstrap_nodes: Vec::new(),
            routing_table_size: 0,
        }
    }

    #[instrument(skip(self, peer_id_bytes, session_key), level = "debug")]
    pub fn with_identity(mut self, peer_id_bytes: [u8; 32], session_key: [u8; 32]) -> Self {
        debug!("Setting DHT identity");
        self.local_identity = Some((peer_id_bytes, session_key));
        self
    }

    #[instrument(skip(self, peers), level = "debug")]
    pub fn with_bootstrap_peers(mut self, peers: Vec<(PeerId, String)>) -> Self {
        debug!(count = peers.len(), "Setting bootstrap peers");
        self.bootstrap_peers = peers.clone();
        self.bootstrap_nodes = peers.iter().map(|(id, _)| *id).collect();
        self
    }

    #[instrument(skip(self, name), level = "debug")]
    pub fn with_protocol_name(mut self, name: String) -> Self {
        debug!(protocol = %name, "Setting protocol name");
        self.protocol_name = name;
        self
    }

    #[instrument(skip(self, limiter), level = "debug")]
    pub fn with_rate_limiter(mut self, limiter: RateLimiter) -> Self {
        debug!("Setting rate limiter");
        self.rate_limiter = Arc::new(limiter);
        self
    }

    #[instrument(skip(self, manager), level = "debug")]
    pub fn with_reputation_manager(mut self, manager: ReputationManager) -> Self {
        debug!("Setting reputation manager");
        self.reputation_manager = Arc::new(manager);
        self
    }

    #[instrument(skip(self, key), level = "debug")]
    pub fn set_session_key(&mut self, peer_id: PeerId, key: [u8; 32]) {
        debug!(peer_id = %peer_id, "Setting session key");
        self.session_keys.insert(peer_id, key);
    }

    #[instrument(skip(self), level = "trace")]
    pub fn is_verified(&self, peer_id: &PeerId) -> bool {
        let verified = self.verified_peers.contains(peer_id);
        trace!(peer_id = %peer_id, verified, "Checked verification status");
        verified
    }

    #[instrument(skip(self), level = "trace")]
    pub fn is_rate_limited(&self, peer_id: &PeerId) -> bool {
        let limited = !self.rate_limiter.check_rate_limit(peer_id);
        trace!(peer_id = %peer_id, rate_limited = limited, "Checked rate limit");
        limited
    }

    #[instrument(skip(self), level = "trace")]
    pub fn get_reputation(&self, peer_id: &PeerId) -> Option<f64> {
        let score = self.reputation_manager.get_score(peer_id);
        trace!(peer_id = %peer_id, ?score, "Retrieved reputation score");
        score
    }

    fn encrypt_peer_record(&self, record: &PeerRecord) -> Option<EncryptedPeerRecord> {
        let (sender_id, session_key) = self.local_identity.as_ref()?;
        
        let plaintext = serde_json::to_vec(record).ok()?;
        let ciphertext = encrypt(&session_key, &plaintext).ok()?;
        
        if ciphertext.len() < DHT_NONCE_SIZE + DHT_TAG_SIZE {
            warn!("Encrypted record too short");
            return None;
        }
        
        let nonce = ciphertext[..DHT_NONCE_SIZE].try_into().ok()?;
        let ciphertext_only = ciphertext[DHT_NONCE_SIZE..].to_vec();
        
        let timestamp = current_timestamp();
        
        let signature = self.sign_data(&ciphertext_only, &nonce)?;
        
        Some(EncryptedPeerRecord {
            sender_id: *sender_id,
            nonce,
            ciphertext: ciphertext_only,
            signature,
            timestamp,
        })
    }

    fn sign_data(&self, data: &[u8], nonce: &[u8]) -> Option<[u8; 64]> {
        let mut sig_input = data.to_vec();
        sig_input.extend_from_slice(nonce);
        
        let mut hasher = sha2::Sha256::new();
        hasher.update(&sig_input);
        let hash = hasher.finalize();
        
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&hash);
        signature[32..].copy_from_slice(&hash);
        
        Some(signature)
    }

    fn verify_signature(&self, data: &[u8], nonce: &[u8], signature: &[u8; 64]) -> bool {
        let mut sig_input = data.to_vec();
        sig_input.extend_from_slice(nonce);
        
        let mut hasher = sha2::Sha256::new();
        hasher.update(&sig_input);
        let hash = hasher.finalize();
        
        signature[..32] == hash[..32] || signature[32..] == hash[..32]
    }

    fn decrypt_peer_record(&self, encrypted: &EncryptedPeerRecord) -> Option<PeerRecord> {
        if let Some((_, local_key)) = &self.local_identity {
            let mut full_ciphertext = Vec::with_capacity(DHT_NONCE_SIZE + encrypted.ciphertext.len());
            full_ciphertext.extend_from_slice(&encrypted.nonce);
            full_ciphertext.extend_from_slice(&encrypted.ciphertext);
            
            if let Ok(plaintext) = decrypt(local_key, &full_ciphertext) {
                if let Ok(record) = serde_json::from_slice::<PeerRecord>(&plaintext) {
                    return Some(record);
                }
            }
        }
        
        for key in self.session_keys.values() {
            let mut full_ciphertext = Vec::with_capacity(DHT_NONCE_SIZE + encrypted.ciphertext.len());
            full_ciphertext.extend_from_slice(&encrypted.nonce);
            full_ciphertext.extend_from_slice(&encrypted.ciphertext);
            
            if let Ok(plaintext) = decrypt(key, &full_ciphertext) {
                if let Ok(record) = serde_json::from_slice::<PeerRecord>(&plaintext) {
                    return Some(record);
                }
            }
        }
        
        None
    }

    pub fn create_encrypted_record(&self, addresses: Vec<String>, session_key: [u8; 32]) -> Option<Record> {
        let (sender_id, _) = self.local_identity.as_ref()?;
        
        let record = PeerRecord {
            peer_id: *sender_id,
            addresses,
            session_key,
            timestamp: current_timestamp(),
            version: 1,
            proof_of_work: vec![],
        };
        
        let encrypted = self.encrypt_peer_record(&record)?;
        
        let key = RecordKey::from(vec![0x76, 0x6e, 0x70, 0x65, 0x65, 0x72]);
        let value = serde_json::to_vec(&encrypted).ok()?;
        
        Some(Record {
            key,
            value,
            publisher: Some(self.local_peer_id),
            expires: Some(SystemTime::now() + Duration::from_secs(RECORD_TTL_SECS)),
        })
    }

    #[instrument(skip(self), level = "info")]
    pub fn add_peer(&mut self, peer_id: PeerId) {
        if self.rate_limiter.check_rate_limit(&peer_id) {
            self.peers.insert(peer_id);
            self.reputation_manager.record_successful_interaction(&peer_id);
            info!(peer_id = %peer_id, total_peers = self.peers.len(), "Peer added");
        } else {
            warn!(peer_id = %peer_id, "Peer is rate limited, not adding");
        }
    }

    #[instrument(skip(self), level = "info")]
    pub fn add_verified_peer(&mut self, peer_id: PeerId) {
        self.verified_peers.insert(peer_id);
        self.peers.insert(peer_id);
        self.reputation_manager.mark_verified(&peer_id);
        info!(
            peer_id = %peer_id,
            total_peers = self.peers.len(),
            verified_count = self.verified_peers.len(),
            "Verified peer added"
        );
    }

    #[instrument(skip(self), level = "info")]
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        info!(peer_id = %peer_id, "Removing peer");
        self.peers.remove(peer_id);
        self.verified_peers.remove(peer_id);
        self.session_keys.remove(peer_id);
        self.reputation_manager.record_failed_interaction(peer_id);
        self.rate_limiter.clear_peer(peer_id);
        info!(
            peer_id = %peer_id,
            remaining_peers = self.peers.len(),
            "Peer removed"
        );
    }

    pub fn get_session_key(&self, peer_id: &PeerId) -> Option<[u8; 32]> {
        self.session_keys.get(peer_id).copied()
    }

    pub fn create_behaviour(&self) -> Result<kad::Behaviour<MemoryStore>, DiscoveryError> {
        let store = MemoryStore::new(self.local_peer_id);
        let mut config = kad::Config::default();
        let protocol = libp2p::StreamProtocol::try_from_owned(self.protocol_name.clone())
            .map_err(|e| DiscoveryError::DhtError(format!("Invalid protocol name: {}", e)))?;
        config.set_protocol_names(vec![protocol]);
        config.set_replication_factor(5);
        config.set_record_ttl(Duration::from_secs(RECORD_TTL_SECS));
        
        Ok(kad::Behaviour::with_config(self.local_peer_id, store, config))
    }

    #[instrument(skip(self, record), level = "debug")]
    pub fn handle_record(&mut self, record: &Record) -> Option<PeerId> {
        trace!("Caching record");
        let cached = CachedRecord {
            record: record.clone(),
            cached_at: Instant::now(),
            access_count: 1,
        };

        {
            let mut cache = self.record_cache.write();
            cache.put(record.key.clone(), cached);
        }

        // Try to parse as encrypted record
        if let Ok(encrypted) = serde_json::from_slice::<EncryptedPeerRecord>(&record.value) {
            trace!("Parsed encrypted record");

            if !self.verify_signature(&encrypted.ciphertext, &encrypted.nonce, &encrypted.signature) {
                warn!("Invalid signature in record, rejecting");
                return None;
            }
            trace!("Signature verified");

            if let Some(peer_record) = self.decrypt_peer_record(&encrypted) {
                let peer_id = PeerId::from_bytes(&peer_record.peer_id).ok()?;

                if !self.proof_of_work.verify(&peer_id) {
                    warn!(peer_id = %peer_id, "Peer has insufficient PoW, rejecting");
                    return None;
                }
                trace!(peer_id = %peer_id, "Proof of work verified");

                self.session_keys.insert(peer_id, peer_record.session_key);
                self.add_verified_peer(peer_id);

                info!(peer_id = %peer_id, "Verified record processed successfully");
                return Some(peer_id);
            } else {
                warn!("Failed to decrypt peer record");
            }
        }

        // Try to parse as plain record
        if let Ok(plain_record) = serde_json::from_slice::<PeerRecord>(&record.value) {
            trace!("Parsed plain record");
            let peer_id = PeerId::from_bytes(&plain_record.peer_id).ok()?;
            self.session_keys.insert(peer_id, plain_record.session_key);
            self.add_peer(peer_id);

            debug!(peer_id = %peer_id, "Plain record processed");
            return Some(peer_id);
        }

        trace!("Could not parse record");
        None
    }

    pub fn get_cached(&self, key: &RecordKey) -> Option<Record> {
        let cache = self.record_cache.read();
        if let Some(cached) = cache.get(key) {
            if cached.cached_at.elapsed() < Duration::from_secs(RECORD_TTL_SECS) {
                return Some(cached.record.clone());
            }
        }
        None
    }

    pub fn prefetch(&mut self, keys: Vec<RecordKey>) {
        let mut queue = self.prefetch_queue.write();
        for key in keys.into_iter().take(PREFETCH_COUNT) {
            if !queue.contains(&key) {
                queue.push_back(key);
            }
        }
    }

    pub fn get_prefetch_keys(&self) -> Vec<RecordKey> {
        let queue = self.prefetch_queue.read();
        queue.iter().take(PREFETCH_COUNT).cloned().collect()
    }

    pub fn update_routing_table_size(&mut self, size: usize) {
        self.routing_table_size = size;
        
        if size > 0 && self.last_prefetch.read().elapsed() > Duration::from_secs(30) {
            *self.last_prefetch.write() = Instant::now();
        }
    }

    pub fn get_bootstrap_nodes(&self) -> Vec<PeerId> {
        self.bootstrap_nodes.clone()
    }

    pub fn needs_bootstrap(&self) -> bool {
        self.routing_table_size < 10
    }
}

impl Discovery for DhtDiscovery {
    #[instrument(skip(self), level = "trace")]
    fn known_peers(&self) -> HashSet<PeerId> {
        let peers = self.peers.clone();
        trace!(count = peers.len(), "Retrieved known peers");
        peers
    }

    #[instrument(skip(self), level = "info")]
    fn start(&mut self) -> Result<(), DiscoveryError> {
        info!(
            bootstrap_peers = self.bootstrap_peers.len(),
            "Starting DHT discovery"
        );

        for (i, (peer_id, addr)) in self.bootstrap_peers.iter().enumerate() {
            debug!(
                index = i,
                peer_id = %peer_id,
                address = %addr,
                "Bootstrap peer configured"
            );
        }

        info!("DHT discovery started");
        Ok(())
    }

    #[instrument(skip(self), level = "info")]
    fn stop(&mut self) -> Result<(), DiscoveryError> {
        info!("Stopping DHT discovery");

        let session_keys_count = self.session_keys.len();
        let verified_count = self.verified_peers.len();

        self.session_keys.clear();
        self.verified_peers.clear();
        self.record_cache.write().clear();

        info!(
            cleared_session_keys = session_keys_count,
            cleared_verified = verified_count,
            "DHT discovery stopped"
        );
        Ok(())
    }
}
