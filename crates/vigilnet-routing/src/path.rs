//! Path selection for circuit building

use rand::seq::SliceRandom;
use std::collections::HashSet;
use tracing::debug;
use serde::{Serialize, Deserialize};

/// Information about a potential relay
#[derive(Debug, Clone)]
pub struct RelayInfo {
    /// Peer ID
    pub peer_id: [u8; 32],
    /// Whether this node can be an exit
    pub is_exit: bool,
    /// Whether this node can be a guard (stable, fast, not overloaded)
    pub is_guard: bool,
    /// Reputation score (0-100)
    pub reputation: u8,
    /// Latency estimate in ms
    pub latency_ms: u32,
    /// Bandwidth capacity in Mbps
    pub bandwidth_mbps: u32,
    /// Current load factor (0.0 - 1.0)
    pub load: f64,
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Whether this relay has been flagged as suspicious
    pub flagged: bool,
}

impl RelayInfo {
    /// Check if relay is suitable as guard node
    pub fn is_suitable_guard(&self) -> bool {
        !self.flagged 
            && self.reputation >= 50 
            && self.uptime_secs >= 86400 
            && self.load < 0.5
    }

    /// Check if relay is suitable as exit
    pub fn is_suitable_exit(&self) -> bool {
        self.is_exit && !self.flagged && self.reputation >= 30
    }
}

/// Path selection strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathStrategy {
    /// Random selection
    Random,
    /// Weighted by reputation
    ReputationWeighted,
    /// Minimum latency
    LowLatency,
    /// Avoid congested nodes
    CongestionAware,
    /// Balanced mix of metrics
    Hybrid,
    /// Guard + middle + exit (Tor-style)
    GuardMiddleExit,
}

impl Default for PathStrategy {
    fn default() -> Self {
        Self::GuardMiddleExit
    }
}

/// Selects paths for circuit building
pub struct PathSelector {
    /// Available relays
    relays: Vec<RelayInfo>,
    /// Selection strategy
    strategy: PathStrategy,
    /// Minimum number of hops
    min_hops: usize,
    /// Maximum number of hops
    max_hops: usize,
    /// Peers to exclude from selection
    excluded: HashSet<[u8; 32]>,
}

impl PathSelector {
    /// Create a new path selector
    pub fn new() -> Self {
        Self {
            relays: Vec::new(),
            strategy: PathStrategy::GuardMiddleExit,
            min_hops: 3,
            max_hops: 3,
            excluded: HashSet::new(),
        }
    }

    /// Set the relay list
    pub fn with_relays(mut self, relays: Vec<RelayInfo>) -> Self {
        self.relays = relays;
        self
    }

    /// Set selection strategy
    pub fn with_strategy(mut self, strategy: PathStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Set hop count range
    pub fn with_hops(mut self, min: usize, max: usize) -> Self {
        self.min_hops = min;
        self.max_hops = max;
        self
    }

    /// Exclude a peer from selection
    pub fn exclude(&mut self, peer_id: [u8; 32]) {
        self.excluded.insert(peer_id);
    }

    /// Add or update a relay
    pub fn add_relay(&mut self, info: RelayInfo) {
        // Check if exists
        if let Some(existing) = self.relays.iter_mut().find(|r| r.peer_id == info.peer_id) {
            *existing = info;
        } else {
            self.relays.push(info);
        }
    }

    /// Select a path for a new circuit
    ///
    /// Returns (entry, middle..., exit) nodes
    pub fn select_path(&self, hop_count: usize) -> Option<Vec<RelayInfo>> {
        if hop_count < self.min_hops || hop_count > self.max_hops {
            return None;
        }

        let available: Vec<_> = self
            .relays
            .iter()
            .filter(|r| !self.excluded.contains(&r.peer_id))
            .collect();

        if available.len() < hop_count {
            debug!(
                "Not enough relays: need {}, have {}",
                hop_count,
                available.len()
            );
            return None;
        }

        let path = match self.strategy {
            PathStrategy::Random => self.select_random(&available, hop_count),
            PathStrategy::ReputationWeighted => self.select_by_reputation(&available, hop_count),
            PathStrategy::LowLatency => self.select_low_latency(&available, hop_count),
            PathStrategy::CongestionAware => self.select_congestion_aware(&available, hop_count),
            PathStrategy::Hybrid => self.select_hybrid(&available, hop_count),
            PathStrategy::GuardMiddleExit => self.select_guard_middle_exit(&available, hop_count),
        };
        
        path
    }

    fn select_random(&self, relays: &[&RelayInfo], count: usize) -> Option<Vec<RelayInfo>> {
        let mut rng = rand::thread_rng();
        let mut selected: Vec<_> = relays.to_vec();
        selected.shuffle(&mut rng);
        
        let path: Vec<_> = selected.into_iter().take(count).cloned().collect();
        
        if path.len() == count {
            Some(path)
        } else {
            None
        }
    }

    fn select_by_reputation(&self, relays: &[&RelayInfo], count: usize) -> Option<Vec<RelayInfo>> {
        let mut sorted: Vec<_> = relays.to_vec();
        sorted.sort_by(|a, b| b.reputation.cmp(&a.reputation));
        
        let path: Vec<_> = sorted.into_iter().take(count).cloned().collect();
        
        if path.len() == count {
            Some(path)
        } else {
            None
        }
    }

    fn select_low_latency(&self, relays: &[&RelayInfo], count: usize) -> Option<Vec<RelayInfo>> {
        let mut sorted: Vec<_> = relays.to_vec();
        sorted.sort_by(|a, b| a.latency_ms.cmp(&b.latency_ms));
        
        let path: Vec<_> = sorted.into_iter().take(count).cloned().collect();
        
        if path.len() == count {
            Some(path)
        } else {
            None
        }
    }

    fn select_congestion_aware(&self, relays: &[&RelayInfo], count: usize) -> Option<Vec<RelayInfo>> {
        // Filter out overloaded relays (load > 0.7)
        let mut candidates: Vec<_> = relays.iter()
            .filter(|r| r.load < 0.7)
            .cloned()
            .collect();

        // If not enough candidates, fall back to all
        if candidates.len() < count {
            candidates = relays.to_vec();
        }

        // Sort by load (ascending)
        candidates.sort_by(|a, b| a.load.partial_cmp(&b.load).unwrap_or(std::cmp::Ordering::Equal));
        
        // Take top N
        let path: Vec<_> = candidates.into_iter().take(count).cloned().collect();

        if path.len() == count {
            Some(path)
        } else {
            None
        }
    }

    fn select_hybrid(&self, relays: &[&RelayInfo], count: usize) -> Option<Vec<RelayInfo>> {
        let mut scored: Vec<(i64, &RelayInfo)> = relays.iter().map(|r| {
            // Score calculation:
            // - Latency: Lower is better (0-1000)
            // - Load: Lower is better (0.0-1.0)
            // - Bandwidth: Higher is better 
            // - Reputation: Higher is better
            
            // Normalize latency (invert)
            let latency_score = 1000u32.saturating_sub(r.latency_ms).clamp(0, 1000) as i64;
            
            // Normalize load (invert)
            let load_score = ((1.0 - r.load) * 1000.0) as i64;
            
            // Bandwidth (cap at 1000 for normalization)
            let bw_score = r.bandwidth_mbps.min(1000) as i64;
            
            // Reputation (scale to 1000)
            let rep_score = (r.reputation as i64) * 10;
            
            // Weighted sum
            // 30% Latency, 30% Load, 20% BW, 20% Reputation
            let total_score = 
                (latency_score * 3) + 
                (load_score * 3) + 
                (bw_score * 2) + 
                (rep_score * 2);
            
            (total_score, *r)
        }).collect();

        // Sort by score descending
        scored.sort_by(|a, b| b.0.cmp(&a.0));

        // Take top candidates
        let path: Vec<_> = scored.into_iter().take(count).map(|(_, r)| r.clone()).collect();

        if path.len() == count {
            Some(path)
        } else {
            None
        }
    }

    fn select_guard_middle_exit(&self, relays: &[&RelayInfo], count: usize) -> Option<Vec<RelayInfo>> {
        if count != 3 {
            return self.select_hybrid(relays, count);
        }

        let mut rng = rand::thread_rng();
        
        let guards: Vec<_> = relays.iter()
            .filter(|r| r.is_suitable_guard())
            .cloned()
            .collect();
        
        let exits: Vec<_> = relays.iter()
            .filter(|r| r.is_suitable_exit())
            .cloned()
            .collect();
        
        if guards.is_empty() || exits.is_empty() {
            return self.select_hybrid(relays, count);
        }
        
        let mut selected_guards: Vec<_> = guards;
        selected_guards.shuffle(&mut rng);
        
        let guard = selected_guards.first()?;
        
        let mut remaining: Vec<_> = relays.iter()
            .filter(|r| r.peer_id != guard.peer_id)
            .cloned()
            .collect();
        remaining.shuffle(&mut rng);
        
        let middle = remaining.first()?;
        
        let mut remaining_after_middle: Vec<_> = remaining.iter()
            .filter(|r| r.peer_id != middle.peer_id && r.is_suitable_exit())
            .cloned()
            .collect();
        
        if remaining_after_middle.is_empty() {
            return self.select_hybrid(relays, count);
        }
        remaining_after_middle.shuffle(&mut rng);
        let exit = remaining_after_middle.first()?;

        Some(vec![guard.clone(), middle.clone(), exit.clone()])
    }
}

impl Default for PathSelector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_relay(peer_id: u8, is_exit: bool, reputation: u8, latency_ms: u32, load: f64, uptime_secs: u64) -> RelayInfo {
        RelayInfo {
            peer_id: [peer_id; 32],
            is_exit,
            is_guard: true,
            reputation,
            latency_ms,
            bandwidth_mbps: 100,
            load,
            uptime_secs,
            flagged: false,
        }
    }

    #[test]
    fn test_guard_middle_exit_selection() {
        let relays = vec![
            create_test_relay(1, true, 80, 50, 0.3, 100000),
            create_test_relay(2, false, 70, 60, 0.4, 100000),
            create_test_relay(3, true, 90, 40, 0.2, 100000),
            create_test_relay(4, true, 60, 100, 0.8, 100000),
            create_test_relay(5, false, 50, 30, 0.1, 100000),
        ];

        let selector = PathSelector::new()
            .with_relays(relays)
            .with_strategy(PathStrategy::GuardMiddleExit);

        let path = selector.select_path(3);
        
        assert!(path.is_some());
        let path = path.unwrap();
        assert_eq!(path.len(), 3);
        
        assert!(path[0].is_suitable_guard());
        assert!(path[2].is_suitable_exit());
    }

    #[test]
    fn test_hybrid_selection() {
        let relays = vec![
            create_test_relay(1, true, 80, 50, 0.3, 100000),
            create_test_relay(2, false, 70, 60, 0.4, 100000),
            create_test_relay(3, true, 90, 40, 0.2, 100000),
        ];

        let selector = PathSelector::new()
            .with_relays(relays)
            .with_strategy(PathStrategy::Hybrid);

        let path = selector.select_path(3);
        
        assert!(path.is_some());
        assert_eq!(path.unwrap().len(), 3);
    }

    #[test]
    fn test_relay_info_guard_suitability() {
        let good_guard = create_test_relay(1, false, 60, 50, 0.3, 100000);
        assert!(good_guard.is_suitable_guard());

        let low_reputation = create_test_relay(2, false, 30, 50, 0.3, 100000);
        assert!(!low_reputation.is_suitable_guard());

        let low_uptime = create_test_relay(3, false, 60, 50, 0.3, 1000);
        assert!(!low_uptime.is_suitable_guard());

        let high_load = create_test_relay(4, false, 60, 50, 0.8, 100000);
        assert!(!high_load.is_suitable_guard());
    }
}
