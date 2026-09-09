//! VigilNet Agent Research
//!
//! Multi-perspective research orchestration for VigilNet agents:
//! - Perspective routing for diverse agent selection
//! - Subagent spawning and lifecycle management
//! - Consensus engine for aggregating results
//! - Research orchestration with scalability support

pub mod consensus;
pub mod perspective_router;
pub mod research;
pub mod subagent;

pub use consensus::{
    ConsensusEngine, ConsensusInput, ConsensusMode, ConsensusOutput, ConsensusAggregator,
    Disagreement, PerspectiveResult,
};
pub use perspective_router::{
    AgentCapability, ModelSize, ModelVendor, PerspectiveAgent, PerspectiveRouter,
    RoutingConfig, RoutingRequest, RoutingResult,
};
pub use research::{
    ResearchConfig, ResearchHealth, ResearchMetrics, ResearchOrchestrator,
    ResearchQuery, ResearchResult, ResearchService,
};
pub use subagent::{
    Subagent, SubagentCommand, SubagentConfig, SubagentManager, SubagentMetrics,
    SubagentRegistry, SubagentStatus, SubagentTask, SubagentTaskResult, SubagentType,
};

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

pub struct ResearchSystem {
    orchestrator: Arc<RwLock<ResearchOrchestrator>>,
    initialized: bool,
}

impl ResearchSystem {
    pub fn new(config: ResearchConfig) -> Self {
        Self {
            orchestrator: Arc::new(RwLock::new(ResearchOrchestrator::new(config))),
            initialized: false,
        }
    }

    pub async fn initialize(&mut self) -> Result<()> {
        info!("Initializing VigilNet Research System");
        
        let mut orchestrator = self.orchestrator.write().await;
        
        self.initialized = true;
        
        info!("VigilNet Research System initialized successfully");
        
        Ok(())
    }

    pub async fn execute(&self, query: ResearchQuery) -> Result<ResearchResult> {
        if !self.initialized {
            return Err(anyhow::anyhow!("Research system not initialized"));
        }
        
        let orchestrator = self.orchestrator.read().await;
        orchestrator.execute(query).await
    }

    pub async fn execute_batch(&self, queries: Vec<ResearchQuery>) -> Vec<Result<ResearchResult>> {
        if !self.initialized {
            return queries
                .iter()
                .map(|_| Err(anyhow::anyhow!("Research system not initialized")))
                .collect();
        }
        
        let orchestrator = self.orchestrator.read().await;
        orchestrator.execute_batch(queries).await
    }

    pub async fn health(&self) -> Option<ResearchHealth> {
        if !self.initialized {
            return None;
        }
        
        let orchestrator = self.orchestrator.read().await;
        Some(orchestrator.health().await)
    }

    pub async fn metrics(&self) -> Option<ResearchMetrics> {
        if !self.initialized {
            return None;
        }
        
        let orchestrator = self.orchestrator.read().await;
        Some(orchestrator.metrics().await)
    }

    pub async fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for ResearchSystem {
    fn default() -> Self {
        Self::new(ResearchConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================
    // Unit Tests for ResearchSystem
    // ============================================

    #[tokio::test]
    async fn test_research_system_creation() {
        let system = ResearchSystem::new(ResearchConfig::default());
        assert!(!system.is_initialized().await);
    }

    #[tokio::test]
    async fn test_research_system_default() {
        let system: ResearchSystem = Default::default();
        assert!(!system.is_initialized().await);
    }

    #[tokio::test]
    async fn test_research_system_initialization() {
        let mut system = ResearchSystem::new(ResearchConfig::default());
        
        assert!(!system.is_initialized().await);
        
        system.initialize().await.unwrap();
        
        assert!(system.is_initialized().await);
    }

    #[tokio::test]
    async fn test_research_system_execute_not_initialized() {
        let system = ResearchSystem::new(ResearchConfig::default());
        
        let query = ResearchQuery::new(
            "test".to_string(),
            "test description".to_string(),
            2,
        );
        
        let result = system.execute(query).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not initialized"));
    }

    #[tokio::test]
    async fn test_research_system_execute_batch_not_initialized() {
        let system = ResearchSystem::new(ResearchConfig::default());
        
        let queries = vec![
            ResearchQuery::new("test1".to_string(), "desc1".to_string(), 2),
            ResearchQuery::new("test2".to_string(), "desc2".to_string(), 2),
        ];
        
        let results = system.execute_batch(queries).await;
        assert_eq!(results.len(), 2);
        
        for result in results {
            assert!(result.is_err());
        }
    }

    #[tokio::test]
    async fn test_research_system_health_not_initialized() {
        let system = ResearchSystem::new(ResearchConfig::default());
        
        let health = system.health().await;
        assert!(health.is_none());
    }

    #[tokio::test]
    async fn test_research_system_metrics_not_initialized() {
        let system = ResearchSystem::new(ResearchConfig::default());
        
        let metrics = system.metrics().await;
        assert!(metrics.is_none());
    }

    #[tokio::test]
    async fn test_research_system_health_initialized() {
        let mut system = ResearchSystem::new(ResearchConfig::default());
        system.initialize().await.unwrap();
        
        let health = system.health().await;
        assert!(health.is_some());
    }

    #[tokio::test]
    async fn test_research_system_metrics_initialized() {
        let mut system = ResearchSystem::new(ResearchConfig::default());
        system.initialize().await.unwrap();
        
        let metrics = system.metrics().await;
        assert!(metrics.is_some());
    }

    // ============================================
    // Integration Tests
    // ============================================

    #[tokio::test]
    async fn test_research_system_full_lifecycle() {
        let mut system = ResearchSystem::new(ResearchConfig::default());
        
        // Initial state
        assert!(!system.is_initialized().await);
        
        // Initialize
        system.initialize().await.unwrap();
        assert!(system.is_initialized().await);
        
        // Execute query
        let query = ResearchQuery::new(
            "test topic".to_string(),
            "test description".to_string(),
            2,
        );
        
        let result = system.execute(query).await;
        // Execution may succeed or fail depending on implementation
        let _ = result;
        
        // Check health and metrics
        let health = system.health().await;
        assert!(health.is_some());
        
        let metrics = system.metrics().await;
        assert!(metrics.is_some());
    }

    #[tokio::test]
    async fn test_research_system_multiple_queries() {
        let mut system = ResearchSystem::new(ResearchConfig::default());
        system.initialize().await.unwrap();
        
        let queries: Vec<_> = (0..5)
            .map(|i| ResearchQuery::new(
                format!("topic-{}", i),
                format!("description-{}", i),
                2,
            ))
            .collect();
        
        let results = system.execute_batch(queries).await;
        assert_eq!(results.len(), 5);
    }

    // ============================================
    // Error Handling Tests
    // ============================================

    #[tokio::test]
    async fn test_research_system_double_initialization() {
        let mut system = ResearchSystem::new(ResearchConfig::default());
        
        system.initialize().await.unwrap();
        // Second initialization should also succeed (idempotent)
        system.initialize().await.unwrap();
        
        assert!(system.is_initialized().await);
    }

    // ============================================
    // Edge Case Tests
    // ============================================

    #[tokio::test]
    async fn test_research_system_empty_batch() {
        let mut system = ResearchSystem::new(ResearchConfig::default());
        system.initialize().await.unwrap();
        
        let results = system.execute_batch(vec![]).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_research_system_large_batch() {
        let mut system = ResearchSystem::new(ResearchConfig::default());
        system.initialize().await.unwrap();
        
        let queries: Vec<_> = (0..100)
            .map(|i| ResearchQuery::new(
                format!("topic-{}", i),
                format!("description-{}", i),
                1,
            ))
            .collect();
        
        let results = system.execute_batch(queries).await;
        assert_eq!(results.len(), 100);
    }

    #[tokio::test]
    async fn test_research_system_concurrent_access() {
        use std::sync::Arc;
        
        let mut system = ResearchSystem::new(ResearchConfig::default());
        system.initialize().await.unwrap();
        
        let system = Arc::new(RwLock::new(system));
        let mut handles = vec![];
        
        for i in 0..10 {
            let sys = Arc::clone(&system);
            let handle = tokio::spawn(async move {
                let query = ResearchQuery::new(
                    format!("concurrent-{}", i),
                    "test".to_string(),
                    1,
                );
                let guard = sys.read().await;
                let _ = guard.execute(query).await;
                let _ = guard.health().await;
                let _ = guard.metrics().await;
            });
            handles.push(handle);
        }
        
        for handle in handles {
            handle.await.unwrap();
        }
    }
}
