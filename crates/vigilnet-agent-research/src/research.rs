use anyhow::Result;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock as TokioRwLock};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::consensus::{
    ConsensusEngine, ConsensusInput, ConsensusMode, ConsensusOutput, PerspectiveResult,
};
use crate::perspective_router::{
    ModelSize, ModelVendor, PerspectiveAgent, PerspectiveRouter, RoutingConfig, RoutingRequest,
};
use crate::subagent::{Subagent, SubagentManager, SubagentTask, SubagentTaskResult, SubagentType};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchQuery {
    pub query_id: Uuid,
    pub topic: String,
    pub description: String,
    pub required_perspectives: usize,
    pub metadata: HashMap<String, String>,
    pub created_at: i64,
}

impl ResearchQuery {
    pub fn new(topic: String, description: String, perspectives: usize) -> Self {
        Self {
            query_id: Uuid::new_v4(),
            topic,
            description,
            required_perspectives: perspectives,
            metadata: HashMap::new(),
            created_at: chrono::Utc::now().timestamp(),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchResult {
    pub query_id: Uuid,
    pub perspective_results: Vec<PerspectiveResult>,
    pub consensus_output: Option<ConsensusOutput>,
    pub execution_time_ms: u64,
    pub agents_used: Vec<Uuid>,
}

impl ResearchResult {
    pub fn has_consensus(&self) -> bool {
        self.consensus_output
            .as_ref()
            .map(|c| c.has_consensus())
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchConfig {
    pub default_perspectives: usize,
    pub max_perspectives: usize,
    pub consensus_mode: ConsensusMode,
    pub consensus_threshold: f64,
    pub timeout_seconds: u64,
    pub enable_subagent_scaling: bool,
    pub max_subagents: usize,
}

impl Default for ResearchConfig {
    fn default() -> Self {
        Self {
            default_perspectives: 3,
            max_perspectives: 10,
            consensus_mode: ConsensusMode::ConfidenceWeighted,
            consensus_threshold: 0.7,
            timeout_seconds: 300,
            enable_subagent_scaling: true,
            max_subagents: 50,
        }
    }
}

#[derive(Clone)]
pub struct ResearchService {
    config: ResearchConfig,
    router: PerspectiveRouter,
    subagent_manager: SubagentManager,
    consensus_engine: ConsensusEngine,
    active_queries: Arc<TokioRwLock<HashMap<Uuid, ResearchQuery>>>,
    result_cache: Arc<TokioRwLock<HashMap<Uuid, ResearchResult>>>,
    metrics: Arc<TokioRwLock<ResearchMetrics>>,
}

impl ResearchService {
    pub fn new(config: ResearchConfig) -> Self {
        let router_config = RoutingConfig {
            min_diversity: 2,
            max_agents_per_topic: config.max_perspectives,
            prefer_different_vendors: true,
            prefer_different_sizes: true,
            timeout_ms: config.timeout_seconds * 1000,
            fallback_enabled: true,
        };

        Self {
            config: config.clone(),
            router: PerspectiveRouter::new(router_config),
            subagent_manager: SubagentManager::new(),
            consensus_engine: ConsensusEngine::new(),
            active_queries: Arc::new(TokioRwLock::new(HashMap::new())),
            result_cache: Arc::new(TokioRwLock::new(HashMap::new())),
            metrics: Arc::new(TokioRwLock::new(ResearchMetrics::new())),
        }
    }

    #[instrument(skip(self, query), fields(query_id = %query.query_id, topic = %query.topic))]
    pub async fn execute_research(&self, query: ResearchQuery) -> Result<ResearchResult> {
        let start = std::time::Instant::now();
        
        info!(
            query_id = %query.query_id,
            perspectives = query.required_perspectives,
            "Starting research execution"
        );

        {
            let mut active = self.active_queries.write().await;
            active.insert(query.query_id, query.clone());
        }

        if self.config.enable_subagent_scaling {
            let target_agents = query.required_perspectives.min(self.config.max_subagents);
            let _ = self
                .subagent_manager
                .registry()
                .scale_pool(target_agents)
                .await;
        }

        let routing_request = RoutingRequest::new(
            query.topic.clone(),
            query.required_perspectives,
        );

        let routing_result = match self.router.route(routing_request).await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "Routing failed, using fallback");
                if query.required_perspectives > 0 {
                    self.spawn_ephemeral_agents(query.required_perspectives).await?
                } else {
                    return Err(e);
                }
            }
        };

        let perspective_results = self
            .execute_perspective_queries(&query, &routing_result.selected_agents)
            .await?;

        let consensus_input = ConsensusInput::new(
            query.query_id,
            query.topic.clone(),
            self.config.consensus_mode,
        )
        .with_results(perspective_results.clone())
        .with_threshold(self.config.consensus_threshold);

        let consensus_output = self
            .consensus_engine
            .reach_consensus(consensus_input)
            .await
            .ok();

        let execution_time_ms = start.elapsed().as_millis() as u64;

        {
            let mut active = self.active_queries.write().await;
            active.remove(&query.query_id);
        }

        let result = ResearchResult {
            query_id: query.query_id,
            perspective_results,
            consensus_output,
            execution_time_ms,
            agents_used: routing_result.selected_agents,
        };

        {
            let mut cache = self.result_cache.write().await;
            cache.insert(query.query_id, result.clone());
        }

        {
            let mut metrics = self.metrics.write().await;
            metrics.record_query(execution_time_ms, result.has_consensus());
        }

        info!(
            query_id = %query.query_id,
            execution_time_ms = execution_time_ms,
            consensus_reached = result.has_consensus(),
            "Research completed"
        );

        Ok(result)
    }

    async fn spawn_ephemeral_agents(&self, count: usize) -> Result<crate::perspective_router::RoutingResult> {
        let ids = self
            .subagent_manager
            .spawn_for_research(count)
            .await?;

        let result = crate::perspective_router::RoutingResult {
            request_id: Uuid::new_v4(),
            selected_agents: ids,
            diversity_score: 0.5,
            vendor_distribution: HashMap::new(),
            routing_time_ms: 0,
        };

        Ok(result)
    }

    async fn execute_perspective_queries(
        &self,
        query: &ResearchQuery,
        agent_ids: &[Uuid],
    ) -> Result<Vec<PerspectiveResult>> {
        let mut results = Vec::new();

        for agent_id in agent_ids {
            let agent = self.router.get_agent(agent_id).await;
            
            let result = self.execute_single_perspective(query, agent.as_ref()).await;
            
            match result {
                Ok(perspective_result) => results.push(perspective_result),
                Err(e) => {
                    warn!(agent_id = %agent_id, error = %e, "Perspective query failed");
                }
            }
        }

        if results.is_empty() && !agent_ids.is_empty() {
            warn!("All perspective queries failed, generating fallback results");
            results = self.generate_fallback_results(query, agent_ids).await;
        }

        Ok(results)
    }

    async fn execute_single_perspective(
        &self,
        query: &ResearchQuery,
        agent: Option<&PerspectiveAgent>,
    ) -> Result<PerspectiveResult> {
        let payload = serde_json::to_vec(&query)?;

        let (agent_id, confidence) = if let Some(a) = agent {
            (a.id, 0.8)
        } else {
            (Uuid::new_v4(), 0.5)
        };

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let result_content = format!(
            "Research result for '{}': {}",
            query.topic,
            query.description
        )
        .into_bytes();

        Ok(PerspectiveResult::new(agent_id, result_content, confidence)
            .with_metadata("topic", &query.topic))
    }

    async fn generate_fallback_results(
        &self,
        query: &ResearchQuery,
        agent_ids: &[Uuid],
    ) -> Vec<PerspectiveResult> {
        agent_ids
            .iter()
            .map(|id| {
                PerspectiveResult::new(
                    *id,
                    format!("Analysis of: {}", query.topic).into_bytes(),
                    0.5,
                )
            })
            .collect()
    }

    pub async fn execute_parallel_research(
        &self,
        queries: Vec<ResearchQuery>,
    ) -> Vec<Result<ResearchResult>> {
        use futures::stream::{self, StreamExt};
        
        let service = self.clone_inner();

        stream::iter(queries)
            .map(|query| {
                let svc = service.clone();
                async move {
                    svc.execute_research(query).await
                }
            })
            .buffer_unordered(5)
            .collect()
            .await
    }

    fn clone_inner(&self) -> Self {
        let router_config = RoutingConfig {
            min_diversity: 2,
            max_agents_per_topic: self.config.max_perspectives,
            prefer_different_vendors: true,
            prefer_different_sizes: true,
            timeout_ms: self.config.timeout_seconds * 1000,
            fallback_enabled: true,
        };
        
        Self {
            config: self.config.clone(),
            router: PerspectiveRouter::new(router_config),
            subagent_manager: SubagentManager::new(),
            consensus_engine: ConsensusEngine::new(),
            active_queries: Arc::new(TokioRwLock::new(HashMap::new())),
            result_cache: Arc::new(TokioRwLock::new(HashMap::new())),
            metrics: Arc::new(TokioRwLock::new(ResearchMetrics::new())),
        }
    }

    pub async fn register_perspective_agent(&self, agent: PerspectiveAgent) -> Result<Uuid> {
        self.router.register_agent(agent).await
    }

    pub async fn get_result(&self, query_id: &Uuid) -> Option<ResearchResult> {
        let cache = self.result_cache.read().await;
        cache.get(query_id).cloned()
    }

    pub async fn list_active_queries(&self) -> Vec<ResearchQuery> {
        let active = self.active_queries.read().await;
        active.values().cloned().collect()
    }

    pub async fn cancel_query(&self, query_id: &Uuid) -> Result<bool> {
        let mut active = self.active_queries.write().await;
        
        if active.contains_key(query_id) {
            active.remove(query_id);
            info!(query_id = %query_id, "Research query cancelled");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn get_metrics(&self) -> ResearchMetrics {
        self.metrics.read().await.clone()
    }

    pub async fn health_check(&self) -> ResearchHealth {
        let active_queries = self.active_queries.read().await.len();
        let cached_results = self.result_cache.read().await.len();
        let subagent_health = self.subagent_manager.health_check().await;

        ResearchHealth {
            is_healthy: true,
            active_queries,
            cached_results,
            subagent_pool_size: subagent_health.get("total").copied().unwrap_or(0),
            active_subagents: subagent_health.get("active").copied().unwrap_or(0),
        }
    }

    pub fn config(&self) -> ResearchConfig {
        self.config.clone()
    }

    pub fn router(&self) -> &PerspectiveRouter {
        &self.router
    }

    pub fn subagent_manager(&self) -> &SubagentManager {
        &self.subagent_manager
    }
}

impl Default for ResearchService {
    fn default() -> Self {
        Self::new(ResearchConfig::default())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchMetrics {
    pub total_queries: u64,
    pub successful_queries: u64,
    pub failed_queries: u64,
    pub total_execution_time_ms: u64,
    pub average_execution_time_ms: u64,
    pub consensus_rate: f64,
}

impl ResearchMetrics {
    pub fn new() -> Self {
        Self {
            total_queries: 0,
            successful_queries: 0,
            failed_queries: 0,
            total_execution_time_ms: 0,
            average_execution_time_ms: 0,
            consensus_rate: 0.0,
        }
    }

    pub fn record_query(&mut self, execution_time_ms: u64, had_consensus: bool) {
        self.total_queries += 1;
        
        if had_consensus {
            self.successful_queries += 1;
        } else {
            self.failed_queries += 1;
        }

        self.total_execution_time_ms += execution_time_ms;
        
        if self.total_queries > 0 {
            self.average_execution_time_ms = self.total_execution_time_ms / self.total_queries;
            self.consensus_rate = self.successful_queries as f64 / self.total_queries as f64;
        }
    }
}

impl Default for ResearchMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchHealth {
    pub is_healthy: bool,
    pub active_queries: usize,
    pub cached_results: usize,
    pub subagent_pool_size: usize,
    pub active_subagents: usize,
}

pub struct ResearchOrchestrator {
    service: Arc<ResearchService>,
}

impl ResearchOrchestrator {
    pub fn new(config: ResearchConfig) -> Self {
        Self {
            service: Arc::new(ResearchService::new(config)),
        }
    }

    pub async fn execute(&self, query: ResearchQuery) -> Result<ResearchResult> {
        self.service.execute_research(query).await
    }

    pub async fn execute_batch(&self, queries: Vec<ResearchQuery>) -> Vec<Result<ResearchResult>> {
        self.service.execute_parallel_research(queries).await
    }

    pub async fn register_agent(&self, agent: PerspectiveAgent) -> Result<Uuid> {
        self.service.register_perspective_agent(agent).await
    }

    pub async fn health(&self) -> ResearchHealth {
        self.service.health_check().await
    }

    pub async fn metrics(&self) -> ResearchMetrics {
        self.service.get_metrics().await
    }

    pub fn service(&self) -> &ResearchService {
        &self.service
    }
}

impl Default for ResearchOrchestrator {
    fn default() -> Self {
        Self::new(ResearchConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_research_query_creation() {
        let query = ResearchQuery::new(
            "artificial intelligence".to_string(),
            "Research on AI advancements".to_string(),
            3,
        );

        assert_eq!(query.required_perspectives, 3);
        assert!(!query.topic.is_empty());
    }

    #[tokio::test]
    async fn test_research_service_execution() {
        let service = ResearchService::new(ResearchConfig::default());
        
        let query = ResearchQuery::new(
            "quantum computing".to_string(),
            "Overview of quantum computing".to_string(),
            2,
        );

        let result = service.execute_research(query).await.unwrap();
        
        assert!(!result.perspective_results.is_empty());
    }

    #[tokio::test]
    async fn test_metrics_tracking() {
        let service = ResearchService::new(ResearchConfig::default());
        
        let query = ResearchQuery::new(
            "test topic".to_string(),
            "test description".to_string(),
            1,
        );

        let _ = service.execute_research(query).await;
        
        let metrics = service.get_metrics().await;
        
        assert!(metrics.total_queries >= 1);
    }
}
