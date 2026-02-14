use anyhow::Result;
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use vigilnet_agent_core::AgentInfo;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ModelVendor {
    OpenAI,
    Anthropic,
    Google,
    Meta,
    Mistral,
    Local,
    Custom(String),
}

impl ModelVendor {
    pub fn from_string(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "openai" | "gpt" => ModelVendor::OpenAI,
            "anthropic" | "claude" => ModelVendor::Anthropic,
            "google" | "gemini" => ModelVendor::Google,
            "meta" | "llama" => ModelVendor::Meta,
            "mistral" => ModelVendor::Mistral,
            "local" => ModelVendor::Local,
            other => ModelVendor::Custom(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ModelSize {
    Small,
    Medium,
    Large,
    XLarge,
}

impl ModelSize {
    pub fn from_string(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "small" | "mini" | "nano" | "8b" | "7b" => ModelSize::Small,
            "medium" | "14b" | "13b" => ModelSize::Medium,
            "large" | "70b" | "65b" | "72b" => ModelSize::Large,
            "xlarge" | "xl" | "400b" | "175b" => ModelSize::XLarge,
            _ => ModelSize::Medium,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCapability {
    pub topic: String,
    pub expertise_level: f64,
    pub keywords: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerspectiveAgent {
    pub id: Uuid,
    pub agent_info: AgentInfo,
    pub vendor: ModelVendor,
    pub model_size: ModelSize,
    pub capabilities: Vec<AgentCapability>,
    pub active: bool,
    pub tasks_completed: u64,
    pub average_latency_ms: u64,
}

impl PerspectiveAgent {
    pub fn new(
        agent_info: AgentInfo,
        vendor: ModelVendor,
        model_size: ModelSize,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            agent_info,
            vendor,
            model_size,
            capabilities: Vec::new(),
            active: true,
            tasks_completed: 0,
            average_latency_ms: 0,
        }
    }

    pub fn with_capabilities(mut self, capabilities: Vec<AgentCapability>) -> Self {
        self.capabilities = capabilities;
        self
    }

    pub fn matches_topic(&self, topic: &str) -> bool {
        let topic_lower = topic.to_lowercase();
        
        for cap in &self.capabilities {
            if cap.topic.to_lowercase().contains(&topic_lower) {
                return true;
            }
            for keyword in &cap.keywords {
                if topic_lower.contains(&keyword.to_lowercase()) {
                    return true;
                }
            }
        }
        
        self.agent_info.has_capability(topic)
    }

    pub fn is_diverse_from(&self, other: &PerspectiveAgent) -> bool {
        self.vendor != other.vendor || self.model_size != other.model_size
    }

    pub fn record_completion(&mut self, latency_ms: u64) {
        self.tasks_completed += 1;
        
        let total_latency = self.average_latency_ms * (self.tasks_completed - 1);
        self.average_latency_ms = (total_latency + latency_ms) / self.tasks_completed;
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }

    pub fn activate(&mut self) {
        self.active = true;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    pub min_diversity: usize,
    pub max_agents_per_topic: usize,
    pub prefer_different_vendors: bool,
    pub prefer_different_sizes: bool,
    pub timeout_ms: u64,
    pub fallback_enabled: bool,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            min_diversity: 2,
            max_agents_per_topic: 5,
            prefer_different_vendors: true,
            prefer_different_sizes: true,
            timeout_ms: 30000,
            fallback_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRequest {
    pub request_id: Uuid,
    pub topic: String,
    pub required_capabilities: Vec<String>,
    pub desired_perspectives: usize,
    pub allow_ephemeral: bool,
}

impl RoutingRequest {
    pub fn new(topic: String, perspectives: usize) -> Self {
        Self {
            request_id: Uuid::new_v4(),
            topic,
            required_capabilities: Vec::new(),
            desired_perspectives: perspectives,
            allow_ephemeral: true,
        }
    }

    pub fn with_capabilities(mut self, capabilities: Vec<String>) -> Self {
        self.required_capabilities = capabilities;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingResult {
    pub request_id: Uuid,
    pub selected_agents: Vec<Uuid>,
    pub diversity_score: f64,
    pub vendor_distribution: HashMap<String, usize>,
    pub routing_time_ms: u64,
}

#[derive(Clone)]
pub struct PerspectiveRouter {
    agents: Arc<DashMap<Uuid, RwLock<PerspectiveAgent>>>,
    topic_index: Arc<DashMap<String, Vec<Uuid>>>,
    config: RoutingConfig,
}

impl PerspectiveRouter {
    pub fn new(config: RoutingConfig) -> Self {
        Self {
            agents: Arc::new(DashMap::new()),
            topic_index: Arc::new(DashMap::new()),
            config,
        }
    }

    #[instrument(skip(self, agent), fields(agent_id = %agent.id, agent_name = %agent.agent_info.name))]
    pub async fn register_agent(&self, agent: PerspectiveAgent) -> Result<Uuid> {
        let agent_id = agent.id;
        let topics: Vec<String> = agent.capabilities.iter().map(|c| c.topic.clone()).collect();
        
        self.agents.insert(agent_id, RwLock::new(agent.clone()));
        
        for topic in &topics {
            let mut index = self.topic_index.entry(topic.clone()).or_insert_with(Vec::new);
            if !index.contains(&agent_id) {
                index.push(agent_id);
            }
        }
        
        if topics.is_empty() {
            let mut index = self.topic_index.entry("general".to_string()).or_insert_with(Vec::new);
            if !index.contains(&agent_id) {
                index.push(agent_id);
            }
        }

        info!(
            agent_id = %agent_id,
            topics = ?topics,
            "Agent registered for perspective routing"
        );

        Ok(agent_id)
    }

    pub async fn unregister_agent(&self, agent_id: &Uuid) -> Result<()> {
        if let Some(agent) = self.agents.remove(agent_id) {
            let agent = agent.read();
            for cap in &agent.capabilities {
                if let Some(mut index) = self.topic_index.get_mut(&cap.topic) {
                    index.retain(|id| id != agent_id);
                }
            }
            info!(agent_id = %agent_id, "Agent unregistered from perspective routing");
        }
        Ok(())
    }

    #[instrument(skip(self), fields(topic = %request.topic, desired = %request.desired_perspectives))]
    pub async fn route(&self, request: RoutingRequest) -> Result<RoutingResult> {
        let start = std::time::Instant::now();
        
        let candidate_ids = self.find_candidate_agents(&request.topic).await;
        
        if candidate_ids.is_empty() {
            warn!(topic = %request.topic, "No agents found for topic");
            return Err(anyhow::anyhow!("No agents available for topic: {}", request.topic));
        }

        let selected = self.select_diverse_agents(&request, &candidate_ids).await?;
        
        let diversity_score = self.calculate_diversity_score(&selected).await;
        let vendor_distribution = self.get_vendor_distribution(&selected).await;
        let routing_time_ms = start.elapsed().as_millis() as u64;

        let result = RoutingResult {
            request_id: request.request_id,
            selected_agents: selected.iter().map(|a| a.id).collect(),
            diversity_score,
            vendor_distribution,
            routing_time_ms,
        };

        debug!(
            request_id = %result.request_id,
            selected = result.selected_agents.len(),
            diversity = result.diversity_score,
            "Routing completed"
        );

        Ok(result)
    }

    async fn find_candidate_agents(&self, topic: &str) -> Vec<Uuid> {
        let mut candidates = Vec::new();
        
        if let Some(topic_ids) = self.topic_index.get(topic) {
            for id in topic_ids.iter() {
                if let Some(agent) = self.agents.get(id) {
                    if agent.read().active {
                        candidates.push(*id);
                    }
                }
            }
        }
        
        if candidates.is_empty() {
            if let Some(general_ids) = self.topic_index.get("general") {
                for id in general_ids.iter() {
                    if let Some(agent) = self.agents.get(id) {
                        if agent.read().active {
                            candidates.push(*id);
                        }
                    }
                }
            }
        }

        for entry in self.agents.iter() {
            let agent = entry.read();
            if agent.active && !candidates.contains(&entry.key()) {
                if agent.matches_topic(topic) {
                    candidates.push(*entry.key());
                }
            }
        }

        candidates
    }

    async fn select_diverse_agents(
        &self,
        request: &RoutingRequest,
        candidate_ids: &[Uuid],
    ) -> Result<Vec<PerspectiveAgent>> {
        let mut selected = Vec::new();
        let mut used_vendors = HashMap::new();
        let mut used_sizes = HashMap::new();

        let mut candidates: Vec<PerspectiveAgent> = candidate_ids
            .iter()
            .filter_map(|id| {
                self.agents.get(id).map(|entry| {
                    let agent = entry.read().clone();
                    agent
                })
            })
            .collect();

        candidates.sort_by(|a, b| {
            b.agent_info.trust_score
                .partial_cmp(&a.agent_info.trust_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        for candidate in candidates {
            if selected.len() >= request.desired_perspectives {
                break;
            }

            if selected.len() >= self.config.max_agents_per_topic {
                break;
            }

            let vendor_key = format!("{:?}", candidate.vendor);
            let size_key = format!("{:?}", candidate.model_size);

            let vendor_ok = !self.config.prefer_different_vendors
                || *used_vendors.get(&vendor_key).unwrap_or(&0) < 2;
            let size_ok = !self.config.prefer_different_sizes
                || *used_sizes.get(&size_key).unwrap_or(&0) < 2;

            if vendor_ok && size_ok {
                let is_diverse = selected.is_empty()
                    || selected.iter().all(|s| candidate.is_diverse_from(s));

                if is_diverse || selected.len() < self.config.min_diversity {
                    selected.push(candidate.clone());
                    *used_vendors.entry(vendor_key).or_insert(0) += 1;
                    *used_sizes.entry(size_key).or_insert(0) += 1;
                }
            }
        }

        if selected.len() < self.config.min_diversity && request.allow_ephemeral {
            info!(
                desired = request.desired_perspectives,
                found = selected.len(),
                "Allowing ephemeral agents for diversity"
            );
        }

        Ok(selected)
    }

    async fn calculate_diversity_score(&self, agents: &[PerspectiveAgent]) -> f64 {
        if agents.is_empty() {
            return 0.0;
        }

        let mut vendor_set = std::collections::HashSet::new();
        let mut size_set = std::collections::HashSet::new();

        for agent in agents {
            vendor_set.insert(agent.vendor.clone());
            size_set.insert(agent.model_size.clone());
        }

        let vendor_score = vendor_set.len() as f64 / 3.0;
        let size_score = size_set.len() as f64 / 3.0;
        
        (vendor_score + size_score).min(1.0)
    }

    async fn get_vendor_distribution(&self, agents: &[PerspectiveAgent]) -> HashMap<String, usize> {
        let mut dist = HashMap::new();
        for agent in agents {
            let key = format!("{:?}", agent.vendor);
            *dist.entry(key).or_insert(0) += 1;
        }
        dist
    }

    pub async fn get_agent(&self, id: &Uuid) -> Option<PerspectiveAgent> {
        self.agents.get(id).map(|e| e.read().clone())
    }

    pub async fn list_agents(&self) -> Vec<PerspectiveAgent> {
        self.agents
            .iter()
            .map(|entry| entry.read().clone())
            .collect()
    }

    pub async fn update_agent_status(&self, id: &Uuid, active: bool) -> Result<()> {
        if let Some(agent) = self.agents.get(id) {
            let mut agent = agent.write();
            if active {
                agent.activate();
            } else {
                agent.deactivate();
            }
        }
        Ok(())
    }

    pub fn config(&self) -> &RoutingConfig {
        &self.config
    }

    pub fn update_config(&mut self, config: RoutingConfig) {
        self.config = config;
    }
}

impl Default for PerspectiveRouter {
    fn default() -> Self {
        Self::new(RoutingConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_agent_registration_and_routing() {
        let router = PerspectiveRouter::new(RoutingConfig::default());
        
        let agent_info = AgentInfo::new(
            vigilnet_agent_core::AgentId::new(libp2p::PeerId::random()),
            "test-agent".to_string(),
            vec!["research".to_string(), "analysis".to_string()],
            "gpt-4".to_string(),
        );
        
        let agent = PerspectiveAgent::new(
            agent_info,
            ModelVendor::OpenAI,
            ModelSize::Large,
        ).with_capabilities(vec![
            AgentCapability {
                topic: "technology".to_string(),
                expertise_level: 0.9,
                keywords: vec!["ai".to_string(), "ml".to_string()],
            }
        ]);
        
        router.register_agent(agent).await.unwrap();
        
        let request = RoutingRequest::new("technology".to_string(), 2);
        let result = router.route(request).await.unwrap();
        
        assert!(!result.selected_agents.is_empty());
    }

    #[tokio::test]
    async fn test_diversity_selection() {
        let router = PerspectiveRouter::new(RoutingConfig::default());
        
        let vendors = vec![
            ModelVendor::OpenAI,
            ModelVendor::Anthropic,
            ModelVendor::Google,
        ];
        
        for (i, vendor) in vendors.iter().enumerate() {
            let agent_info = AgentInfo::new(
                vigilnet_agent_core::AgentId::new(libp2p::PeerId::random()),
                format!("agent-{}", i),
                vec!["research".to_string()],
                "default".to_string(),
            );
            
            let agent = PerspectiveAgent::new(
                agent_info,
                vendor.clone(),
                ModelSize::Large,
            ).with_capabilities(vec![
                AgentCapability {
                    topic: "science".to_string(),
                    expertise_level: 0.8,
                    keywords: vec![],
                }
            ]);
            
            router.register_agent(agent).await.unwrap();
        }
        
        let request = RoutingRequest::new("science".to_string(), 3);
        let result = router.route(request).await.unwrap();
        
        assert!(result.diversity_score > 0.0);
    }
}
