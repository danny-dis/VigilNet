use anyhow::Result;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use vigilnet_agent_core::AgentInfo;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SubagentType {
    Ephemeral,
    Persistent,
    Pooled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SubagentStatus {
    Starting,
    Running,
    Idle,
    Processing,
    Completed,
    Failed,
    Cancelled,
    Terminated,
}

impl SubagentStatus {
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            SubagentStatus::Starting
                | SubagentStatus::Running
                | SubagentStatus::Idle
                | SubagentStatus::Processing
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubagentConfig {
    pub max_concurrent_tasks: usize,
    pub timeout_seconds: u64,
    pub max_retries: u32,
    pub memory_limit_mb: Option<u64>,
    pub auto_restart: bool,
    pub priority: i32,
}

impl Default for SubagentConfig {
    fn default() -> Self {
        Self {
            max_concurrent_tasks: 3,
            timeout_seconds: 300,
            max_retries: 2,
            memory_limit_mb: Some(2048),
            auto_restart: false,
            priority: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubagentTask {
    pub task_id: Uuid,
    pub subagent_id: Uuid,
    pub payload: Vec<u8>,
    pub metadata: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub deadline: Option<DateTime<Utc>>,
}

impl SubagentTask {
    pub fn new(subagent_id: Uuid, payload: Vec<u8>) -> Self {
        Self {
            task_id: Uuid::new_v4(),
            subagent_id,
            payload,
            metadata: HashMap::new(),
            created_at: Utc::now(),
            deadline: None,
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    pub fn with_deadline(mut self, deadline: DateTime<Utc>) -> Self {
        self.deadline = Some(deadline);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubagentTaskResult {
    pub task_id: Uuid,
    pub subagent_id: Uuid,
    pub success: bool,
    pub result: Option<Vec<u8>>,
    pub error: Option<String>,
    pub execution_time_ms: u64,
    pub completed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubagentMetrics {
    pub tasks_processed: u64,
    pub tasks_succeeded: u64,
    pub tasks_failed: u64,
    pub total_execution_time_ms: u64,
    pub average_execution_time_ms: u64,
    pub peak_memory_usage_mb: u64,
    pub current_memory_usage_mb: u64,
}

impl SubagentMetrics {
    pub fn new() -> Self {
        Self {
            tasks_processed: 0,
            tasks_succeeded: 0,
            tasks_failed: 0,
            total_execution_time_ms: 0,
            average_execution_time_ms: 0,
            peak_memory_usage_mb: 0,
            current_memory_usage_mb: 0,
        }
    }

    pub fn record_task(&mut self, result: &SubagentTaskResult) {
        self.tasks_processed += 1;
        
        if result.success {
            self.tasks_succeeded += 1;
        } else {
            self.tasks_failed += 1;
        }
        
        self.total_execution_time_ms += result.execution_time_ms;
        
        if self.tasks_processed > 0 {
            self.average_execution_time_ms = self.total_execution_time_ms / self.tasks_processed;
        }
    }

    pub fn success_rate(&self) -> f64 {
        if self.tasks_processed == 0 {
            return 0.0;
        }
        self.tasks_succeeded as f64 / self.tasks_processed as f64
    }
}

impl Default for SubagentMetrics {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Subagent {
    pub id: Uuid,
    pub name: String,
    pub subagent_type: SubagentType,
    pub config: SubagentConfig,
    pub agent_info: Option<AgentInfo>,
    pub status: RwLock<SubagentStatus>,
    pub metrics: RwLock<SubagentMetrics>,
    pub parent_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub last_active: RwLock<DateTime<Utc>>,
    pub task_queue_size: RwLock<usize>,
    cancel_tx: RwLock<Option<oneshot::Sender<()>>>,
}

impl Subagent {
    pub fn new(name: String, subagent_type: SubagentType) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            subagent_type,
            config: SubagentConfig::default(),
            agent_info: None,
            status: RwLock::new(SubagentStatus::Starting),
            metrics: RwLock::new(SubagentMetrics::new()),
            parent_id: None,
            created_at: Utc::now(),
            last_active: RwLock::new(Utc::now()),
            task_queue_size: RwLock::new(0),
            cancel_tx: RwLock::new(None),
        }
    }

    pub fn with_config(mut self, config: SubagentConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_agent_info(mut self, info: AgentInfo) -> Self {
        self.agent_info = Some(info);
        self
    }

    pub fn with_parent(mut self, parent_id: Uuid) -> Self {
        self.parent_id = Some(parent_id);
        self
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn status(&self) -> SubagentStatus {
        self.status.read().clone()
    }

    pub fn is_active(&self) -> bool {
        self.status.read().is_active()
    }

    pub fn set_status(&self, status: SubagentStatus) {
        *self.status.write() = status;
    }

    pub fn metrics(&self) -> SubagentMetrics {
        self.metrics.read().clone()
    }

    pub fn record_task_result(&self, result: SubagentTaskResult) {
        self.metrics.write().record_task(&result);
    }

    pub fn update_last_active(&self) {
        *self.last_active.write() = Utc::now();
    }

    pub fn queue_size(&self) -> usize {
        *self.task_queue_size.read()
    }

    pub fn increment_queue(&self) {
        let mut size = self.task_queue_size.write();
        *size += 1;
    }

    pub fn decrement_queue(&self) {
        let mut size = self.task_queue_size.write();
        *size = size.saturating_sub(1);
    }

    pub fn cancel(&self) -> bool {
        if let Some(tx) = self.cancel_tx.write().take() {
            let _ = tx.send(());
            info!(subagent_id = %self.id, "Subagent cancellation requested");
            true
        } else {
            false
        }
    }

    pub fn create_cancellation_channel(&self) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        *self.cancel_tx.write() = Some(tx);
        rx
    }

    pub fn uptime(&self) -> chrono::Duration {
        Utc::now() - self.created_at
    }

    pub fn idle_time(&self) -> chrono::Duration {
        Utc::now() - *self.last_active.read()
    }
}

impl std::fmt::Debug for Subagent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subagent")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("type", &self.subagent_type)
            .field("status", &self.status())
            .field("metrics", &self.metrics())
            .finish()
    }
}

pub enum SubagentCommand {
    ExecuteTask {
        task: SubagentTask,
        response_tx: oneshot::Sender<SubagentTaskResult>,
    },
    GetStatus,
    GetMetrics,
    UpdateConfig {
        config: SubagentConfig,
    },
    Cancel,
    Shutdown,
}

#[derive(Clone)]
pub struct SubagentRegistry {
    subagents: Arc<DashMap<Uuid, Subagent>>,
    task_sender: Arc<mpsc::Sender<SubagentCommand>>,
}

impl SubagentRegistry {
    pub fn new() -> Self {
        let (task_sender, _) = mpsc::channel(100);
        
        Self {
            subagents: Arc::new(DashMap::new()),
            task_sender: Arc::new(task_sender),
        }
    }

    pub fn with_channel(mut self, sender: mpsc::Sender<SubagentCommand>) -> Self {
        self.task_sender = Arc::new(sender);
        self
    }

    #[instrument(skip(self), fields(subagent_name = %name, subagent_type = ?subagent_type))]
    pub async fn spawn_subagent(
        &self,
        name: String,
        subagent_type: SubagentType,
        config: Option<SubagentConfig>,
    ) -> Result<Uuid> {
        let mut subagent = Subagent::new(name.clone(), subagent_type.clone());
        
        if let Some(cfg) = config {
            subagent = subagent.with_config(cfg);
        }

        let subagent_id = subagent.id();
        
        self.subagents.insert(subagent_id, subagent);
        
        info!(
            subagent_id = %subagent_id,
            subagent_name = name,
            subagent_type = ?subagent_type,
            "Subagent spawned"
        );

        Ok(subagent_id)
    }

    pub async fn spawn_ephemeral(&self, parent_id: Uuid) -> Result<Uuid> {
        let name = format!("ephemeral-{}", Uuid::new_v4());
        self.spawn_subagent(name, SubagentType::Ephemeral, None).await
    }

    pub async fn spawn_persistent(&self, name: String) -> Result<Uuid> {
        self.spawn_subagent(name, SubagentType::Persistent, None).await
    }

    pub async fn terminate_subagent(&self, subagent_id: &Uuid) -> Result<()> {
        if let Some(subagent) = self.subagents.get(subagent_id) {
            subagent.set_status(SubagentStatus::Terminated);
            let _ = subagent.cancel();
            
            self.subagents.remove(subagent_id);
            
            info!(subagent_id = %subagent_id, "Subagent terminated");
        }
        Ok(())
    }

    pub async fn submit_task(&self, task: SubagentTask) -> Result<SubagentTaskResult> {
        let subagent_id = task.subagent_id;
        
        let subagent = self.subagents.get(&subagent_id)
            .ok_or_else(|| anyhow::anyhow!("Subagent not found: {}", subagent_id))?;
        
        if !subagent.is_active() {
            return Err(anyhow::anyhow!("Subagent is not active: {}", subagent_id));
        }

        subagent.increment_queue();
        subagent.set_status(SubagentStatus::Processing);
        subagent.update_last_active();

        let (response_tx, response_rx) = oneshot::channel();
        
        let cmd = SubagentCommand::ExecuteTask {
            task,
            response_tx,
        };
        
        self.task_sender.send(cmd).await.map_err(|e| {
            anyhow::anyhow!("Failed to submit task: {}", e)
        })?;

        let result = response_rx.await.map_err(|e| {
            anyhow::anyhow!("Task execution failed: {}", e)
        })?;

        subagent.decrement_queue();
        
        if result.success {
            subagent.set_status(SubagentStatus::Idle);
        } else {
            subagent.set_status(SubagentStatus::Failed);
        }
        
        subagent.record_task_result(result.clone());

        Ok(result)
    }

    pub async fn get_subagent(&self, id: &Uuid) -> Option<Subagent> {
        self.subagents.get(id).map(|e| e.clone())
    }

    pub async fn list_subagents(&self) -> Vec<Subagent> {
        self.subagents.iter().map(|e| e.value().clone()).collect()
    }

    pub async fn list_active(&self) -> Vec<Uuid> {
        self.subagents
            .iter()
            .filter(|e| e.value().is_active())
            .map(|e| *e.key())
            .collect()
    }

    pub async fn get_status(&self, id: &Uuid) -> Option<SubagentStatus> {
        self.subagents.get(id).map(|e| e.status())
    }

    pub async fn get_metrics(&self, id: &Uuid) -> Option<SubagentMetrics> {
        self.subagents.get(id).map(|e| e.metrics())
    }

    pub async fn cancel_subagent(&self, id: &Uuid) -> Result<bool> {
        if let Some(subagent) = self.subagents.get(id) {
            let cancelled = subagent.cancel();
            if cancelled {
                subagent.set_status(SubagentStatus::Cancelled);
            }
            Ok(cancelled)
        } else {
            Ok(false)
        }
    }

    pub async fn scale_pool(&self, target_size: usize) -> Result<Vec<Uuid>> {
        let current_count = self.subagents.len();
        let mut spawned_ids = Vec::new();
        
        if target_size > current_count {
            let to_spawn = target_size - current_count;
            
            info!(current = current_count, target = target_size, spawning = to_spawn, "Scaling up subagent pool");
            
            for i in 0..to_spawn {
                let name = format!("pooled-agent-{}", i);
                if let Ok(id) = self.spawn_subagent(name, SubagentType::Pooled, None).await {
                    spawned_ids.push(id);
                }
            }
        } else if target_size < current_count {
            let to_terminate = current_count - target_size;
            
            info!(current = current_count, target = target_size, terminating = to_terminate, "Scaling down subagent pool");
            
            let pooled: Vec<Uuid> = self.subagents
                .iter()
                .filter(|e| e.value().subagent_type == SubagentType::Pooled)
                .map(|e| *e.key())
                .collect();
            
            for id in pooled.iter().take(to_terminate) {
                let _ = self.terminate_subagent(id).await;
            }
        }
        
        Ok(spawned_ids)
    }

    pub fn task_sender(&self) -> Arc<mpsc::Sender<SubagentCommand>> {
        self.task_sender.clone()
    }

    pub fn subagent_count(&self) -> usize {
        self.subagents.len()
    }

    pub fn active_count(&self) -> usize {
        self.subagents.iter().filter(|e| e.value().is_active()).count()
    }
}

impl Default for SubagentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct SubagentManager {
    registry: Arc<SubagentRegistry>,
    max_ephemeral: usize,
    max_pooled: usize,
}

impl SubagentManager {
    pub fn new() -> Self {
        Self {
            registry: Arc::new(SubagentRegistry::new()),
            max_ephemeral: 10,
            max_pooled: 50,
        }
    }

    pub fn with_limits(mut self, max_ephemeral: usize, max_pooled: usize) -> Self {
        self.max_ephemeral = max_ephemeral;
        self.max_pooled = max_pooled;
        self
    }

    pub fn registry(&self) -> &SubagentRegistry {
        &self.registry
    }

    #[instrument(skip(self))]
    pub async fn spawn_for_research(&self, perspective_count: usize) -> Result<Vec<Uuid>> {
        let mut spawned = Vec::new();
        
        let ephemeral_count = perspective_count.min(self.max_ephemeral);
        
        info!(count = ephemeral_count, "Spawning ephemeral subagents for research");
        
        for _ in 0..ephemeral_count {
            match self.registry.spawn_ephemeral(Uuid::new_v4()).await {
                Ok(id) => spawned.push(id),
                Err(e) => {
                    warn!(error = %e, "Failed to spawn ephemeral subagent");
                }
            }
        }
        
        Ok(spawned)
    }

    pub async fn cleanup_idle(&self, idle_threshold_seconds: u64) -> Result<u64> {
        let threshold = chrono::Duration::seconds(idle_threshold_seconds as i64);
        let mut cleaned = 0u64;
        
        let subagents: Vec<Uuid> = self.registry.list_subagents()
            .await
            .iter()
            .filter(|s| s.subagent_type == SubagentType::Ephemeral && s.idle_time() > threshold)
            .map(|s| s.id)
            .collect();
        
        for id in subagents {
            if self.registry.terminate_subagent(&id).await.is_ok() {
                cleaned += 1;
            }
        }
        
        info!(cleaned = cleaned, "Cleaned up idle ephemeral subagents");
        
        Ok(cleaned)
    }

    pub async fn health_check(&self) -> HashMap<String, usize> {
        let mut health = HashMap::new();
        
        let subagents = self.registry.list_subagents().await;
        
        health.insert("total".to_string(), subagents.len());
        health.insert("active".to_string(), subagents.iter().filter(|s| s.is_active()).count());
        health.insert("ephemeral".to_string(), subagents.iter().filter(|s| s.subagent_type == SubagentType::Ephemeral).count());
        health.insert("persistent".to_string(), subagents.iter().filter(|s| s.subagent_type == SubagentType::Persistent).count());
        health.insert("pooled".to_string(), subagents.iter().filter(|s| s.subagent_type == SubagentType::Pooled).count());
        
        health
    }
}

impl Default for SubagentManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_subagent_spawn() {
        let registry = SubagentRegistry::new();
        
        let id = registry.spawn_subagent(
            "test-agent".to_string(),
            SubagentType::Ephemeral,
            None,
        ).await.unwrap();
        
        assert!(registry.get_subagent(&id).await.is_some());
        assert_eq!(registry.subagent_count(), 1);
    }

    #[tokio::test]
    async fn test_subagent_lifecycle() {
        let registry = SubagentRegistry::new();
        
        let id = registry.spawn_persistent("persistent-agent".to_string()).await.unwrap();
        
        let subagent = registry.get_subagent(&id).await.unwrap();
        assert_eq!(subagent.status(), SubagentStatus::Starting);
        
        registry.terminate_subagent(&id).await.unwrap();
        
        assert!(registry.get_subagent(&id).await.is_none());
    }

    #[tokio::test]
    async fn test_pool_scaling() {
        let registry = SubagentRegistry::new();
        
        registry.scale_pool(5).await.unwrap();
        assert_eq!(registry.subagent_count(), 5);
        
        registry.scale_pool(3).await.unwrap();
        assert_eq!(registry.subagent_count(), 3);
    }
}
