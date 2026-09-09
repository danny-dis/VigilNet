//! Agent registry for tracking and discovering VigilNet agents

use crate::agent::{AgentId, AgentInfo, AgentError, Result as AgentResult};
use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, info, instrument, warn};

/// Registry for tracking all known agents
pub struct AgentRegistry {
    agents: DashMap<AgentId, AgentInfo>,
    capability_index: DashMap<String, HashSet<AgentId>>,
    online_peers: RwLock<HashSet<AgentId>>,
    local_agent: RwLock<Option<AgentInfo>>,
}

impl AgentRegistry {
    pub fn new() -> Self {
        Self {
            agents: DashMap::new(),
            capability_index: DashMap::new(),
            online_peers: RwLock::new(HashSet::new()),
            local_agent: RwLock::new(None),
        }
    }

    pub fn with_local_agent(mut self, agent: AgentInfo) -> Self {
        *self.local_agent.write() = Some(agent.clone());
        self.register(agent).ok();
        self
    }

    #[instrument(skip(self))]
    pub fn register(&self, info: AgentInfo) -> AgentResult<()> {
        let peer_id = info.id.clone();

        self.agents.insert(info.id.clone(), info.clone());

        for capability in &info.capabilities {
            self.capability_index
                .entry(capability.clone())
                .or_insert_with(HashSet::new)
                .insert(peer_id.clone());
        }

        if info.is_online {
            self.online_peers.write().insert(peer_id);
        }

        debug!(peer_id = %peer_id, name = %info.name, "Agent registered");
        Ok(())
    }

    pub fn unregister(&self, agent_id: &AgentId) -> AgentResult<AgentInfo> {
        if let Some((_, info)) = self.agents.remove(agent_id) {
            for capability in &info.capabilities {
                if let Some(mut ids) = self.capability_index.get_mut(capability) {
                    ids.remove(agent_id);
                }
            }
            self.online_peers.write().remove(agent_id);
            info!(peer_id = %agent_id, "Agent unregistered");
            Ok(info)
        } else {
            Err(AgentError::NotFound(agent_id.to_string()))
        }
    }

    pub fn get(&self, agent_id: &AgentId) -> Option<AgentInfo> {
        self.agents.get(agent_id).map(|r| r.clone())
    }

    pub fn update(&self, info: AgentInfo) -> AgentResult<()> {
        let agent_id = info.id.clone();

        if !self.agents.contains_key(&agent_id) {
            return Err(AgentError::NotFound(agent_id.to_string()));
        }

        self.agents.insert(agent_id, info);
        Ok(())
    }

    pub fn update_online_status(&self, agent_id: &AgentId, online: bool) -> AgentResult<()> {
        if let Some(mut info) = self.agents.get_mut(agent_id) {
            info.set_online(online);
            if online {
                self.online_peers.write().insert(agent_id.clone());
            } else {
                self.online_peers.write().remove(agent_id);
            }
            Ok(())
        } else {
            Err(AgentError::NotFound(agent_id.to_string()))
        }
    }

    pub fn update_latency(&self, agent_id: &AgentId, latency_ns: u64) -> AgentResult<()> {
        if let Some(mut info) = self.agents.get_mut(agent_id) {
            info.update_latency(latency_ns);
            Ok(())
        } else {
            Err(AgentError::NotFound(agent_id.to_string()))
        }
    }

    #[instrument(skip(self, capability))]
    pub fn find_by_capability(&self, capability: &str) -> Vec<AgentInfo> {
        self.capability_index
            .get(capability)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.get(id))
                    .filter(|info| info.is_online)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn find_by_model(&self, model_type: &str) -> Vec<AgentInfo> {
        self.agents
            .iter()
            .filter(|r| {
                r.model_type.eq_ignore_ascii_case(model_type) && r.is_online
            })
            .map(|r| r.clone())
            .collect()
    }

    pub fn get_all(&self) -> Vec<AgentInfo> {
        self.agents.iter().map(|r| r.clone()).collect()
    }

    pub fn get_online(&self) -> Vec<AgentInfo> {
        self.agents
            .iter()
            .filter(|r| r.is_online)
            .map(|r| r.clone())
            .collect()
    }

    pub fn get_online_ids(&self) -> HashSet<AgentId> {
        self.online_peers.read().clone()
    }

    pub fn count(&self) -> usize {
        self.agents.len()
    }

    pub fn online_count(&self) -> usize {
        self.online_peers.read().len()
    }

    pub fn get_local_agent(&self) -> Option<AgentInfo> {
        self.local_agent.read().clone()
    }

    pub fn get_capabilities(&self) -> Vec<String> {
        self.capability_index
            .iter()
            .map(|r| r.key().clone())
            .collect()
    }

    pub fn get_best_agent(&self, capability: &str) -> Option<AgentInfo> {
        self.find_by_capability(capability)
            .into_iter()
            .max_by(|a, b| {
                a.trust_score
                    .partial_cmp(&b.trust_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }

    pub fn get_lowest_latency_agent(&self, capability: &str) -> Option<AgentInfo> {
        self.find_by_capability(capability)
            .into_iter()
            .filter(|info| info.latency_ns > 0)
            .min_by_key(|info| info.latency_ns)
    }

    pub fn cleanup_stale(&self, max_age_secs: i64) -> Vec<AgentId> {
        let now = chrono::Utc::now().timestamp();
        let mut removed = Vec::new();

        let stale: Vec<AgentId> = self
            .agents
            .iter()
            .filter(|r| now - r.last_seen > max_age_secs)
            .map(|r| r.id.clone())
            .collect();

        for id in stale {
            if self.unregister(&id).is_ok() {
                removed.push(id);
            }
        }

        if !removed.is_empty() {
            warn!(count = removed.len(), "Cleaned up stale agents");
        }

        removed
    }

    pub fn import_agents(&self, agents: Vec<AgentInfo>) {
        for agent in agents {
            if let Err(e) = self.register(agent) {
                warn!(error = %e, "Failed to import agent");
            }
        }
    }

    pub fn export_agents(&self) -> Vec<AgentInfo> {
        self.get_all()
    }
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for AgentRegistry {
    fn clone(&self) -> Self {
        Self {
            agents: DashMap::new(),
            capability_index: DashMap::new(),
            online_peers: RwLock::new(HashSet::new()),
            local_agent: RwLock::new(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::PeerId;

    // ============================================
    // Unit Tests for Core Functionality
    // ============================================

    #[test]
    fn test_registry_creation() {
        let registry = AgentRegistry::new();
        assert_eq!(registry.count(), 0);
        assert_eq!(registry.online_count(), 0);
        assert!(registry.get_local_agent().is_none());
    }

    #[test]
    fn test_default_registry() {
        let registry: AgentRegistry = Default::default();
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_agent_registration() {
        let registry = AgentRegistry::new();
        let peer_id = PeerId::random();
        let agent = AgentInfo::new(
            AgentId::new(peer_id),
            "test-agent".to_string(),
            vec!["finance".to_string()],
            "gpt-4".to_string(),
        );

        registry.register(agent.clone()).unwrap();
        assert_eq!(registry.count(), 1);
        
        let retrieved = registry.get(&agent.id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "test-agent");
    }

    #[test]
    fn test_agent_unregistration() {
        let registry = AgentRegistry::new();
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let agent = AgentInfo::new(
            agent_id.clone(),
            "test-agent".to_string(),
            vec!["finance".to_string()],
            "gpt-4".to_string(),
        );

        registry.register(agent).unwrap();
        assert_eq!(registry.count(), 1);

        let removed = registry.unregister(&agent_id).unwrap();
        assert_eq!(removed.name, "test-agent");
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_unregister_nonexistent_agent() {
        let registry = AgentRegistry::new();
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);

        let result = registry.unregister(&agent_id);
        assert!(result.is_err());
        
        match result {
            Err(AgentError::NotFound(_)) => {},
            _ => panic!("Expected NotFound error"),
        }
    }

    #[test]
    fn test_get_nonexistent_agent() {
        let registry = AgentRegistry::new();
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);

        assert!(registry.get(&agent_id).is_none());
    }

    #[test]
    fn test_capability_index() {
        let registry = AgentRegistry::new();
        let peer_id1 = PeerId::random();
        let peer_id2 = PeerId::random();
        
        let agent1 = AgentInfo::new(
            AgentId::new(peer_id1),
            "agent1".to_string(),
            vec!["finance".to_string(), "tech".to_string()],
            "gpt-4".to_string(),
        );
        
        let agent2 = AgentInfo::new(
            AgentId::new(peer_id2),
            "agent2".to_string(),
            vec!["finance".to_string()],
            "claude-3".to_string(),
        );

        registry.register(agent1).unwrap();
        registry.register(agent2).unwrap();

        let finance_agents = registry.find_by_capability("finance");
        assert_eq!(finance_agents.len(), 2);

        let tech_agents = registry.find_by_capability("tech");
        assert_eq!(tech_agents.len(), 1);
    }

    #[test]
    fn test_find_by_model() {
        let registry = AgentRegistry::new();
        
        let agent1 = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "agent1".to_string(),
            vec![],
            "gpt-4".to_string(),
        );
        
        let agent2 = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "agent2".to_string(),
            vec![],
            "claude-3".to_string(),
        );
        
        let agent3 = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "agent3".to_string(),
            vec![],
            "gpt-4".to_string(),
        );

        registry.register(agent1).unwrap();
        registry.register(agent2).unwrap();
        registry.register(agent3).unwrap();

        let gpt4_agents = registry.find_by_model("gpt-4");
        assert_eq!(gpt4_agents.len(), 2);
    }

    #[test]
    fn test_get_all_agents() {
        let registry = AgentRegistry::new();
        
        for i in 0..5 {
            let agent = AgentInfo::new(
                AgentId::new(PeerId::random()),
                format!("agent-{}", i),
                vec![],
                "model".to_string(),
            );
            registry.register(agent).unwrap();
        }

        let all = registry.get_all();
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn test_get_online_agents() {
        let registry = AgentRegistry::new();
        
        let online_agent = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "online".to_string(),
            vec![],
            "model".to_string(),
        );
        
        let mut offline_agent = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "offline".to_string(),
            vec![],
            "model".to_string(),
        );
        offline_agent.set_online(false);

        registry.register(online_agent).unwrap();
        registry.register(offline_agent).unwrap();

        let online = registry.get_online();
        assert_eq!(online.len(), 1);
        assert_eq!(online[0].name, "online");
    }

    #[test]
    fn test_get_online_ids() {
        let registry = AgentRegistry::new();
        
        let agent = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "test".to_string(),
            vec![],
            "model".to_string(),
        );
        
        registry.register(agent.clone()).unwrap();
        
        let online_ids = registry.get_online_ids();
        assert!(online_ids.contains(&agent.id));
    }

    #[test]
    fn test_update_agent() {
        let registry = AgentRegistry::new();
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        
        let agent = AgentInfo::new(
            agent_id.clone(),
            "original".to_string(),
            vec![],
            "model".to_string(),
        );
        
        registry.register(agent).unwrap();
        
        let mut updated = AgentInfo::new(
            agent_id.clone(),
            "updated".to_string(),
            vec!["new-cap".to_string()],
            "new-model".to_string(),
        );
        updated.trust_score = 0.5;
        
        registry.update(updated).unwrap();
        
        let retrieved = registry.get(&agent_id).unwrap();
        assert_eq!(retrieved.name, "updated");
        assert_eq!(retrieved.trust_score, 0.5);
    }

    #[test]
    fn test_update_nonexistent_agent() {
        let registry = AgentRegistry::new();
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        
        let agent = AgentInfo::new(
            agent_id.clone(),
            "test".to_string(),
            vec![],
            "model".to_string(),
        );
        
        let result = registry.update(agent);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_online_status() {
        let registry = AgentRegistry::new();
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        
        let agent = AgentInfo::new(
            agent_id.clone(),
            "test".to_string(),
            vec![],
            "model".to_string(),
        );
        
        registry.register(agent).unwrap();
        assert_eq!(registry.online_count(), 1);
        
        registry.update_online_status(&agent_id, false).unwrap();
        assert_eq!(registry.online_count(), 0);
        
        let retrieved = registry.get(&agent_id).unwrap();
        assert!(!retrieved.is_online);
    }

    #[test]
    fn test_update_latency() {
        let registry = AgentRegistry::new();
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        
        let agent = AgentInfo::new(
            agent_id.clone(),
            "test".to_string(),
            vec![],
            "model".to_string(),
        );
        
        registry.register(agent).unwrap();
        registry.update_latency(&agent_id, 1_000_000).unwrap();
        
        let retrieved = registry.get(&agent_id).unwrap();
        assert_eq!(retrieved.latency_ns, 1_000_000);
    }

    #[test]
    fn test_get_best_agent() {
        let registry = AgentRegistry::new();
        
        let agent1 = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "agent1".to_string(),
            vec!["compute".to_string()],
            "model".to_string(),
        );
        
        let agent2 = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "agent2".to_string(),
            vec!["compute".to_string()],
            "model".to_string(),
        );
        
        registry.register(agent1).unwrap();
        registry.register(agent2).unwrap();
        
        let best = registry.get_best_agent("compute");
        assert!(best.is_some());
    }

    #[test]
    fn test_get_lowest_latency_agent() {
        let registry = AgentRegistry::new();
        
        let agent1 = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "agent1".to_string(),
            vec!["compute".to_string()],
            "model".to_string(),
        );
        
        let agent2 = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "agent2".to_string(),
            vec!["compute".to_string()],
            "model".to_string(),
        );
        
        registry.register(agent1.clone()).unwrap();
        registry.register(agent2.clone()).unwrap();
        
        registry.update_latency(&agent1.id, 1_000_000).unwrap();
        registry.update_latency(&agent2.id, 500_000).unwrap();
        
        let lowest = registry.get_lowest_latency_agent("compute");
        assert!(lowest.is_some());
        assert_eq!(lowest.unwrap().latency_ns, 500_000);
    }

    #[test]
    fn test_get_capabilities() {
        let registry = AgentRegistry::new();
        
        let agent = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "test".to_string(),
            vec!["cap1".to_string(), "cap2".to_string()],
            "model".to_string(),
        );
        
        registry.register(agent).unwrap();
        
        let caps = registry.get_capabilities();
        assert_eq!(caps.len(), 2);
    }

    #[test]
    fn test_cleanup_stale_agents() {
        let registry = AgentRegistry::new();
        
        // Register a recent agent
        let recent_agent = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "recent".to_string(),
            vec![],
            "model".to_string(),
        );
        registry.register(recent_agent.clone()).unwrap();
        
        // Register an old agent by manipulating last_seen
        let mut old_agent = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "old".to_string(),
            vec![],
            "model".to_string(),
        );
        old_agent.last_seen = chrono::Utc::now().timestamp() - 10000; // Very old
        registry.register(old_agent.clone()).unwrap();
        
        let removed = registry.cleanup_stale(3600); // 1 hour threshold
        assert_eq!(removed.len(), 1);
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn test_import_agents() {
        let registry = AgentRegistry::new();
        
        let agents: Vec<AgentInfo> = (0..10).map(|i| {
            AgentInfo::new(
                AgentId::new(PeerId::random()),
                format!("imported-{}", i),
                vec![format!("cap-{}", i)],
                "model".to_string(),
            )
        }).collect();
        
        registry.import_agents(agents);
        assert_eq!(registry.count(), 10);
    }

    #[test]
    fn test_export_agents() {
        let registry = AgentRegistry::new();
        
        for i in 0..5 {
            let agent = AgentInfo::new(
                AgentId::new(PeerId::random()),
                format!("agent-{}", i),
                vec![],
                "model".to_string(),
            );
            registry.register(agent).unwrap();
        }
        
        let exported = registry.export_agents();
        assert_eq!(exported.len(), 5);
    }

    #[test]
    fn test_with_local_agent() {
        let local_agent = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "local".to_string(),
            vec!["cap1".to_string()],
            "gpt-4".to_string(),
        );
        
        let registry = AgentRegistry::new().with_local_agent(local_agent.clone());
        
        assert!(registry.get_local_agent().is_some());
        assert_eq!(registry.count(), 1);
    }

    // ============================================
    // Integration Tests
    // ============================================

    #[test]
    fn test_full_agent_lifecycle() {
        let registry = AgentRegistry::new();
        
        // Register agent
        let agent = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "lifecycle".to_string(),
            vec!["compute".to_string()],
            "gpt-4".to_string(),
        );
        let agent_id = agent.id.clone();
        
        registry.register(agent).unwrap();
        assert_eq!(registry.count(), 1);
        
        // Update status
        registry.update_online_status(&agent_id, false).unwrap();
        registry.update_latency(&agent_id, 1_000_000).unwrap();
        
        // Update info
        let mut updated = registry.get(&agent_id).unwrap();
        updated.name = "updated-name".to_string();
        registry.update(updated).unwrap();
        
        // Find by capability
        let found = registry.find_by_capability("compute");
        assert!(found.is_empty()); // Offline agents not returned
        
        // Bring online
        registry.update_online_status(&agent_id, true).unwrap();
        let found = registry.find_by_capability("compute");
        assert_eq!(found.len(), 1);
        
        // Unregister
        registry.unregister(&agent_id).unwrap();
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_concurrent_registrations() {
        use std::thread;
        
        let registry = Arc::new(AgentRegistry::new());
        let mut handles = vec![];
        
        for i in 0..10 {
            let reg = Arc::clone(&registry);
            let handle = thread::spawn(move || {
                let agent = AgentInfo::new(
                    AgentId::new(PeerId::random()),
                    format!("agent-{}", i),
                    vec![format!("cap-{}", i)],
                    "model".to_string(),
                );
                reg.register(agent).unwrap();
            });
            handles.push(handle);
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        assert_eq!(registry.count(), 10);
    }

    #[test]
    fn test_registry_clone() {
        let registry = AgentRegistry::new();
        
        let agent = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "test".to_string(),
            vec!["cap".to_string()],
            "model".to_string(),
        );
        
        registry.register(agent).unwrap();
        
        let cloned = registry.clone();
        // Clone should be empty (as per implementation)
        assert_eq!(cloned.count(), 0);
    }

    // ============================================
    // Error Handling Tests
    // ============================================

    #[test]
    fn test_duplicate_registration() {
        let registry = AgentRegistry::new();
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        
        let agent1 = AgentInfo::new(
            agent_id.clone(),
            "agent1".to_string(),
            vec!["cap".to_string()],
            "model".to_string(),
        );
        
        let agent2 = AgentInfo::new(
            agent_id.clone(),
            "agent2".to_string(),
            vec!["cap".to_string()],
            "model".to_string(),
        );
        
        registry.register(agent1).unwrap();
        // Second registration should succeed (overwrites)
        registry.register(agent2).unwrap();
        
        let retrieved = registry.get(&agent_id).unwrap();
        assert_eq!(retrieved.name, "agent2");
    }

    #[test]
    fn test_update_online_status_nonexistent() {
        let registry = AgentRegistry::new();
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        
        let result = registry.update_online_status(&agent_id, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_latency_nonexistent() {
        let registry = AgentRegistry::new();
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        
        let result = registry.update_latency(&agent_id, 1_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_find_by_capability_empty() {
        let registry = AgentRegistry::new();
        let result = registry.find_by_capability("nonexistent");
        assert!(result.is_empty());
    }

    #[test]
    fn test_find_by_model_empty() {
        let registry = AgentRegistry::new();
        let result = registry.find_by_model("nonexistent");
        assert!(result.is_empty());
    }

    #[test]
    fn test_get_best_agent_empty() {
        let registry = AgentRegistry::new();
        let result = registry.get_best_agent("nonexistent");
        assert!(result.is_none());
    }

    #[test]
    fn test_get_lowest_latency_agent_empty() {
        let registry = AgentRegistry::new();
        let result = registry.get_lowest_latency_agent("nonexistent");
        assert!(result.is_none());
    }

    #[test]
    fn test_cleanup_stale_no_agents() {
        let registry = AgentRegistry::new();
        let removed = registry.cleanup_stale(3600);
        assert!(removed.is_empty());
    }

    // ============================================
    // Edge Case Tests
    // ============================================

    #[test]
    fn test_empty_capability_list() {
        let registry = AgentRegistry::new();
        let agent = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "test".to_string(),
            vec![],
            "model".to_string(),
        );
        
        registry.register(agent).unwrap();
        assert_eq!(registry.get_capabilities().len(), 0);
    }

    #[test]
    fn test_many_capabilities() {
        let registry = AgentRegistry::new();
        let caps: Vec<String> = (0..100).map(|i| format!("cap-{}", i)).collect();
        
        let agent = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "test".to_string(),
            caps,
            "model".to_string(),
        );
        
        registry.register(agent).unwrap();
        assert_eq!(registry.get_capabilities().len(), 100);
    }

    #[test]
    fn test_capability_case_sensitivity() {
        let registry = AgentRegistry::new();
        let agent = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "test".to_string(),
            vec!["Finance".to_string()],
            "model".to_string(),
        );
        
        registry.register(agent).unwrap();
        
        // Case-sensitive lookup in capability index
        let finance_agents = registry.find_by_capability("Finance");
        assert_eq!(finance_agents.len(), 1);
        
        // Different case won't match
        let finance_lower = registry.find_by_capability("finance");
        assert_eq!(finance_lower.len(), 0);
    }

    #[test]
    fn test_large_registry() {
        let registry = AgentRegistry::new();
        
        for i in 0..1000 {
            let agent = AgentInfo::new(
                AgentId::new(PeerId::random()),
                format!("agent-{}", i),
                vec![format!("cap-{}", i % 10)],
                "model".to_string(),
            );
            registry.register(agent).unwrap();
        }
        
        assert_eq!(registry.count(), 1000);
        
        let cap0_agents = registry.find_by_capability("cap-0");
        assert_eq!(cap0_agents.len(), 100);
    }

    #[test]
    fn test_offline_agents_not_in_capability_search() {
        let registry = AgentRegistry::new();
        
        let mut agent = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "test".to_string(),
            vec!["compute".to_string()],
            "model".to_string(),
        );
        agent.set_online(false);
        
        registry.register(agent).unwrap();
        
        let online = registry.find_by_capability("compute");
        assert!(online.is_empty());
    }

    #[test]
    fn test_multiple_agents_same_capability() {
        let registry = AgentRegistry::new();
        
        for i in 0..5 {
            let agent = AgentInfo::new(
                AgentId::new(PeerId::random()),
                format!("agent-{}", i),
                vec!["shared-cap".to_string()],
                "model".to_string(),
            );
            registry.register(agent).unwrap();
        }
        
        let agents = registry.find_by_capability("shared-cap");
        assert_eq!(agents.len(), 5);
    }

    #[test]
    fn test_trust_score_ranking() {
        let registry = AgentRegistry::new();
        
        let mut agent1 = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "agent1".to_string(),
            vec!["compute".to_string()],
            "model".to_string(),
        );
        agent1.trust_score = 0.3;
        
        let mut agent2 = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "agent2".to_string(),
            vec!["compute".to_string()],
            "model".to_string(),
        );
        agent2.trust_score = 0.9;
        
        registry.register(agent1).unwrap();
        registry.register(agent2).unwrap();
        
        let best = registry.get_best_agent("compute").unwrap();
        assert_eq!(best.trust_score, 0.9);
    }

    #[test]
    fn test_latency_zero_filtering() {
        let registry = AgentRegistry::new();
        
        let agent = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "test".to_string(),
            vec!["compute".to_string()],
            "model".to_string(),
        );
        
        registry.register(agent.clone()).unwrap();
        // Agent has latency_ns = 0 by default
        
        let lowest = registry.get_lowest_latency_agent("compute");
        // Should be None because latency is 0 (filtered out)
        assert!(lowest.is_none());
    }

    #[test]
    fn test_capability_removed_on_unregister() {
        let registry = AgentRegistry::new();
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        
        let agent = AgentInfo::new(
            agent_id.clone(),
            "test".to_string(),
            vec!["temp-cap".to_string()],
            "model".to_string(),
        );
        
        registry.register(agent).unwrap();
        assert_eq!(registry.find_by_capability("temp-cap").len(), 1);
        
        registry.unregister(&agent_id).unwrap();
        assert_eq!(registry.find_by_capability("temp-cap").len(), 0);
    }

    #[test]
    fn test_partial_cleanup() {
        let registry = AgentRegistry::new();
        
        // Register some agents with different ages
        for i in 0..5 {
            let mut agent = AgentInfo::new(
                AgentId::new(PeerId::random()),
                format!("agent-{}", i),
                vec![],
                "model".to_string(),
            );
            
            if i < 3 {
                // Make these old
                agent.last_seen = chrono::Utc::now().timestamp() - 7200; // 2 hours ago
            }
            
            registry.register(agent).unwrap();
        }
        
        let removed = registry.cleanup_stale(3600); // 1 hour threshold
        assert_eq!(removed.len(), 3);
        assert_eq!(registry.count(), 2);
    }

    #[test]
    fn test_empty_registry_operations() {
        let registry = AgentRegistry::new();
        
        assert!(registry.get_all().is_empty());
        assert!(registry.get_online().is_empty());
        assert!(registry.get_capabilities().is_empty());
        assert_eq!(registry.count(), 0);
        assert_eq!(registry.online_count(), 0);
    }

    #[test]
    fn test_register_unregister_multiple_times() {
        let registry = AgentRegistry::new();
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        
        for i in 0..5 {
            let agent = AgentInfo::new(
                agent_id.clone(),
                format!("agent-{}", i),
                vec![format!("cap-{}", i)],
                "model".to_string(),
            );
            
            registry.register(agent).unwrap();
            assert_eq!(registry.count(), 1);
            
            let retrieved = registry.get(&agent_id).unwrap();
            assert_eq!(retrieved.name, format!("agent-{}", i));
            
            registry.unregister(&agent_id).unwrap();
            assert_eq!(registry.count(), 0);
        }
    }

    #[test]
    fn test_import_with_failures() {
        let registry = AgentRegistry::new();
        
        let valid_agent = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "valid".to_string(),
            vec![],
            "model".to_string(),
        );
        
        // Import should handle duplicates gracefully
        registry.import_agents(vec![valid_agent.clone(), valid_agent]);
        assert_eq!(registry.count(), 1); // Second registration overwrites first
    }

    #[test]
    fn test_online_count_consistency() {
        let registry = AgentRegistry::new();
        
        let mut agent = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "test".to_string(),
            vec![],
            "model".to_string(),
        );
        agent.set_online(false);
        
        registry.register(agent.clone()).unwrap();
        assert_eq!(registry.online_count(), 0);
        
        registry.update_online_status(&agent.id, true).unwrap();
        assert_eq!(registry.online_count(), 1);
        
        registry.update_online_status(&agent.id, false).unwrap();
        assert_eq!(registry.online_count(), 0);
    }

    #[test]
    fn test_find_by_capability_filters_offline() {
        let registry = AgentRegistry::new();
        
        let agent1 = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "online".to_string(),
            vec!["cap".to_string()],
            "model".to_string(),
        );
        
        let mut agent2 = AgentInfo::new(
            AgentId::new(PeerId::random()),
            "offline".to_string(),
            vec!["cap".to_string()],
            "model".to_string(),
        );
        agent2.set_online(false);
        
        registry.register(agent1).unwrap();
        registry.register(agent2).unwrap();
        
        let found = registry.find_by_capability("cap");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "online");
    }
}
