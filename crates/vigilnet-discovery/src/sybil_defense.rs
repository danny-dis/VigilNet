use libp2p::PeerId;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::{debug, info, warn};

const DEFAULT_DIFFICULTY: u32 = 20;
const MAX_REPUTATION_SCORE: f64 = 100.0;
const MIN_REPUTATION_SCORE: f64 = -100.0;
const REPUTATION_DECAY_HOURS: u64 = 24;

#[derive(Debug, Clone)]
pub struct ProofOfWork {
    pub difficulty: u32,
    pub nonce: Arc<AtomicU64>,
}

#[derive(Debug, Clone)]
pub struct PoWProof {
    pub nonce: u64,
    pub public_key_bytes: Vec<u8>,
    pub timestamp: u64,
}

impl ProofOfWork {
    pub fn new(difficulty: u32) -> Self {
        Self { 
            difficulty, 
            nonce: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn default() -> Self {
        Self { 
            difficulty: DEFAULT_DIFFICULTY, 
            nonce: Arc::new(AtomicU64::new(rand::random())),
        }
    }

    pub fn verify(&self, peer_id: &PeerId) -> bool {
        let hash = peer_id.to_bytes();
        self.count_leading_zeros(&hash) >= self.difficulty
    }

    pub fn verify_with_proof(&self, proof: &PoWProof) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(&proof.public_key_bytes);
        hasher.update(&proof.nonce.to_le_bytes());
        hasher.update(&proof.timestamp.to_le_bytes());
        let result = hasher.finalize();
        
        self.count_leading_zeros(&result) >= self.difficulty
    }

    pub fn generate_proof(&self, public_key_bytes: &[u8]) -> Option<PoWProof> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut nonce = self.nonce.fetch_add(1, Ordering::Relaxed);
        
        for _ in 0..10000 {
            let mut hasher = Sha256::new();
            hasher.update(public_key_bytes);
            hasher.update(&nonce.to_le_bytes());
            hasher.update(&timestamp.to_le_bytes());
            let result = hasher.finalize();
            
            if self.count_leading_zeros(&result) >= self.difficulty {
                return Some(PoWProof {
                    nonce,
                    public_key_bytes: public_key_bytes.to_vec(),
                    timestamp,
                });
            }
            nonce += 1;
        }
        
        None
    }

    fn count_leading_zeros(&self, bytes: &[u8]) -> u32 {
        let mut count = 0u32;
        for &byte in bytes {
            if byte == 0 {
                count += 8;
            } else {
                count += byte.leading_zeros();
                break;
            }
        }
        count
    }
}

#[derive(Debug, Clone)]
pub struct PeerReputation {
    pub peer_id: PeerId,
    pub score: f64,
    pub verified: bool,
    pub first_seen: u64,
    pub last_seen: u64,
    pub successful_interactions: u64,
    pub failed_interactions: u64,
    pub relay_count: u64,
}

impl PeerReputation {
    pub fn new(peer_id: PeerId) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            peer_id,
            score: 0.0,
            verified: false,
            first_seen: now,
            last_seen: now,
            successful_interactions: 0,
            failed_interactions: 0,
            relay_count: 0,
        }
    }

    pub fn record_successful_interaction(&mut self) {
        self.successful_interactions += 1;
        self.score = (self.score + 0.1).min(MAX_REPUTATION_SCORE);
        self.last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn record_failed_interaction(&mut self) {
        self.failed_interactions += 1;
        self.score = (self.score - 1.0).max(MIN_REPUTATION_SCORE);
        self.last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn record_relay_usage(&mut self) {
        self.relay_count += 1;
        self.score = (self.score + 0.5).min(MAX_REPUTATION_SCORE);
    }

    pub fn mark_verified(&mut self) {
        self.verified = true;
        self.score = (self.score + 10.0).min(MAX_REPUTATION_SCORE);
    }

    pub fn decay(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let hours_since_last_seen = (now - self.last_seen) / 3600;
        if hours_since_last_seen > 0 {
            let decay = (hours_since_last_seen as f64) * 0.5;
            self.score = (self.score - decay).max(MIN_REPUTATION_SCORE);
        }
    }
}

pub struct ReputationManager {
    reputations: Arc<RwLock<HashMap<PeerId, PeerReputation>>>,
    min_score_for_connection: f64,
}

impl ReputationManager {
    pub fn new(min_score_for_connection: f64) -> Self {
        Self {
            reputations: Arc::new(RwLock::new(HashMap::new())),
            min_score_for_connection,
        }
    }

    pub fn get_or_create(&self, peer_id: PeerId) -> PeerReputation {
        let mut reputations = self.reputations.write();
        if let Some(rep) = reputations.get(&peer_id).cloned() {
            rep
        } else {
            let rep = PeerReputation::new(peer_id);
            reputations.insert(peer_id, rep.clone());
            rep
        }
    }

    pub fn record_successful_interaction(&self, peer_id: &PeerId) {
        let mut reputations = self.reputations.write();
        if let Some(rep) = reputations.get_mut(peer_id) {
            rep.record_successful_interaction();
        }
    }

    pub fn record_failed_interaction(&self, peer_id: &PeerId) {
        let mut reputations = self.reputations.write();
        if let Some(rep) = reputations.get_mut(peer_id) {
            rep.record_failed_interaction();
        }
    }

    pub fn record_relay_usage(&self, peer_id: &PeerId) {
        let mut reputations = self.reputations.write();
        if let Some(rep) = reputations.get_mut(peer_id) {
            rep.record_relay_usage();
        }
    }

    pub fn mark_verified(&self, peer_id: &PeerId) {
        let mut reputations = self.reputations.write();
        if let Some(rep) = reputations.get_mut(peer_id) {
            rep.mark_verified();
        }
    }

    pub fn is_allowed(&self, peer_id: &PeerId) -> bool {
        let reputations = self.reputations.read();
        if let Some(rep) = reputations.get(peer_id) {
            rep.score >= self.min_score_for_connection || rep.verified
        } else {
            true
        }
    }

    pub fn get_score(&self, peer_id: &PeerId) -> Option<f64> {
        let reputations = self.reputations.read();
        reputations.get(peer_id).map(|r| r.score)
    }

    pub fn decay_all(&self) {
        let mut reputations = self.reputations.write();
        for rep in reputations.values_mut() {
            rep.decay();
        }
    }

    pub fn top_peers(&self, limit: usize) -> Vec<PeerId> {
        let reputations = self.reputations.read();
        let mut peers: Vec<_> = reputations.values()
            .filter(|r| r.score >= self.min_score_for_connection || r.verified)
            .collect();
        
        peers.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        peers.into_iter()
            .take(limit)
            .map(|r| r.peer_id)
            .collect()
    }
}

pub struct RateLimiter {
    requests_per_peer: Arc<RwLock<HashMap<PeerId, Vec<u64>>>>,
    max_requests_per_window: usize,
    window_seconds: u64,
}

impl RateLimiter {
    pub fn new(max_requests_per_window: usize, window_seconds: u64) -> Self {
        Self {
            requests_per_peer: Arc::new(RwLock::new(HashMap::new())),
            max_requests_per_window,
            window_seconds,
        }
    }

    pub fn check_rate_limit(&self, peer_id: &PeerId) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut requests = self.requests_per_peer.write();
        
        if let Some(timestamps) = requests.get_mut(peer_id) {
            timestamps.retain(|&ts| now - ts < self.window_seconds);
            
            if timestamps.len() >= self.max_requests_per_window {
                return false;
            }
            
            timestamps.push(now);
            true
        } else {
            requests.insert(*peer_id, vec![now]);
            true
        }
    }

    pub fn record_request(&self, peer_id: &PeerId) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut requests = self.requests_per_peer.write();
        let timestamps = requests.entry(*peer_id).or_insert_with(Vec::new);
        
        timestamps.retain(|&ts| now - ts < self.window_seconds);
        timestamps.push(now);
    }

    pub fn clear_peer(&self, peer_id: &PeerId) {
        let mut requests = self.requests_per_peer.write();
        requests.remove(peer_id);
    }

    pub fn clear_expired(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut requests = self.requests_per_peer.write();
        for timestamps in requests.values_mut() {
            timestamps.retain(|&ts| now - ts < self.window_seconds);
        }
    }
}

pub struct DisjointPathQuery {
    pub num_paths: usize,
    pub replication_factor: usize,
}

impl DisjointPathQuery {
    pub fn new(num_paths: usize) -> Self {
        Self { 
            num_paths,
            replication_factor: 3,
        }
    }

    pub async fn find_providers(&self, _key: &libp2p::kad::RecordKey) -> Vec<PeerId> {
        vec![]
    }

    pub fn get_bucket_ranges(&self, num_buckets: usize) -> Vec<(u64, u64)> {
        let max_value = u64::MAX;
        let bucket_size = max_value / num_buckets as u64;
        
        (0..num_buckets)
            .map(|i| (i as u64 * bucket_size, (i + 1) as u64 * bucket_size))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_generation() {
        let pow = ProofOfWork::new(8);
        let public_key = vec![0u8; 32];
        let proof = pow.generate_proof(&public_key);
        assert!(proof.is_some());
        assert!(pow.verify_with_proof(&proof.unwrap()));
    }

    #[test]
    fn test_reputation_scoring() {
        let peer_id = PeerId::random();
        let mut rep = PeerReputation::new(peer_id);
        
        for _ in 0..10 {
            rep.record_successful_interaction();
        }
        
        assert!(rep.score > 0.0);
        
        for _ in 0..5 {
            rep.record_failed_interaction();
        }
        
        assert!(rep.score < 10.0);
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(5, 60);
        let peer_id = PeerId::random();
        
        for _ in 0..5 {
            assert!(limiter.check_rate_limit(&peer_id));
        }
        
        assert!(!limiter.check_rate_limit(&peer_id));
    }
}
