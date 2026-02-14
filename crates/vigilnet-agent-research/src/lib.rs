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

    #[tokio::test]
    async fn test_research_system_initialization() {
        let mut system = ResearchSystem::new(ResearchConfig::default());
        
        assert!(!system.is_initialized().await);
        
        system.initialize().await.unwrap();
        
        assert!(system.is_initialized().await);
    }

    #[tokio::test]
    async fn test_research_system_execution() {
        let mut system = ResearchSystem::new(ResearchConfig::default());
        system.initialize().await.unwrap();
        
        let query = ResearchQuery::new(
            "machine learning".to_string(),
            "Deep dive into ML".to_string(),
            2,
        );
        
        let result = system.execute(query).await.unwrap();
        
        assert!(result.execution_time_ms > 0);
    }
}
