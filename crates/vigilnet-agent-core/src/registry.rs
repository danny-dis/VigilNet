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

    #[test]
    fn test_agent_registration() {
        let registry = AgentRegistry::new();
        let agent = AgentInfo::new(
            AgentId::from(PeerId::random()),
            "test".to_string(),
            vec!["finance".to_string()],
            "gpt-4".to_string(),
        );

        registry.register(agent.clone()).unwrap();
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn test_capability_lookup() {
        let registry = AgentRegistry::new();
        let agent1 = AgentInfo::new(
            AgentId::from(PeerId::random()),
            "agent1".to_string(),
            vec!["finance".to_string()],
            "gpt-4".to_string(),
        );
        let agent2 = AgentInfo::new(
            AgentId::from(PeerId::random()),
            "agent2".to_string(),
            vec!["tech".to_string()],
            "claude-3".to_string(),
        );

        registry.register(agent1).unwrap();
        registry.register(agent2).unwrap();

        let finance_agents = registry.find_by_capability("finance");
        assert_eq!(finance_agents.len(), 1);
    }
}
