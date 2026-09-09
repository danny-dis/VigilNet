//! VigilNet Health Check System
//!
//! Provides comprehensive health monitoring and status reporting.
//! Supports both simple liveness checks and detailed health status.
//!
//! # Example
//!
//! ```rust
//! use vigilnet_core::health::{HealthChecker, HealthStatus, ComponentHealth};
//!
//! let mut checker = HealthChecker::new();
//! checker.register_component("network", || {
//!     // Check network connectivity
//!     Ok(())
//! });
//!
//! let status = checker.check().await;
//! println!("System is: {}", status.status);
//! ```

use crate::VERSION;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Overall health status of the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Current status: "healthy", "degraded", "unhealthy"
    pub status: HealthState,
    /// Software version
    pub version: String,
    /// Timestamp of the health check
    pub timestamp: u64,
    /// System uptime in seconds
    pub uptime_secs: u64,
    /// Individual component health
    pub components: Vec<ComponentHealth>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Health state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthState {
    /// All systems operational
    Healthy,
    /// Some components experiencing issues
    Degraded,
    /// Critical failure
    Unhealthy,
}

impl HealthState {
    /// Merge two health states
    pub fn merge(self, other: HealthState) -> HealthState {
        match (self, other) {
            (HealthState::Unhealthy, _) | (_, HealthState::Unhealthy) => HealthState::Unhealthy,
            (HealthState::Degraded, _) | (_, HealthState::Degraded) => HealthState::Degraded,
            _ => HealthState::Healthy,
        }
    }

    /// Check if healthy
    pub fn is_healthy(&self) -> bool {
        matches!(self, HealthState::Healthy)
    }

    /// HTTP status code
    pub fn http_status(&self) -> u16 {
        match self {
            HealthState::Healthy => 200,
            HealthState::Degraded => 200,
            HealthState::Unhealthy => 503,
        }
    }
}

/// Individual component health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component name
    pub name: String,
    /// Component status
    pub status: HealthState,
    /// Human-readable message
    pub message: String,
    /// Last check timestamp
    pub last_check: u64,
    /// Response time in milliseconds
    pub response_time_ms: u64,
    /// Additional details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Health check function type
pub type HealthCheckFn = Box<
    dyn Fn() -> Pin<Box<dyn Future<Output = HealthCheckResult> + Send>> + Send + Sync,
>;

/// Result of a health check
#[derive(Debug, Clone)]
pub enum HealthCheckResult {
    /// Component is healthy
    Healthy(Option<String>),
    /// Component is degraded but functional
    Degraded(String),
    /// Component is unhealthy
    Unhealthy(String),
}

impl HealthCheckResult {
    /// Get the status
    pub fn status(&self) -> HealthState {
        match self {
            HealthCheckResult::Healthy(_) => HealthState::Healthy,
            HealthCheckResult::Degraded(_) => HealthState::Degraded,
            HealthCheckResult::Unhealthy(_) => HealthState::Unhealthy,
        }
    }

    /// Get the message
    pub fn message(&self) -> String {
        match self {
            HealthCheckResult::Healthy(Some(m)) => m.clone(),
            HealthCheckResult::Healthy(None) => "OK".to_string(),
            HealthCheckResult::Degraded(m) => m.clone(),
            HealthCheckResult::Unhealthy(m) => m.clone(),
        }
    }
}

/// Health checker that manages component health checks
pub struct HealthChecker {
    /// Registered health check components
    components: RwLock<HashMap<String, HealthCheckFn>>,
    /// Start time for uptime calculation
    started_at: Instant,
    /// Cached health status
    cache: RwLock<Option<(HealthStatus, Instant)>>,
    /// Cache TTL
    cache_ttl: Duration,
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new() -> Self {
        Self {
            components: RwLock::new(HashMap::new()),
            started_at: Instant::now(),
            cache: RwLock::new(None),
            cache_ttl: Duration::from_secs(5),
        }
    }

    /// Set cache TTL
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Register a component health check
    pub async fn register_component<F, Fut>(&self, name: &str, check: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = HealthCheckResult> + Send + 'static,
    {
        let check_fn: HealthCheckFn = Box::new(move || Box::pin(check()));
        self.components.write().await.insert(name.to_string(), check_fn);
        info!("Registered health check component: {}", name);
    }

    /// Register a simple sync health check
    pub async fn register_sync_check<F>(&self, name: &str, check: F)
    where
        F: Fn() -> HealthCheckResult + Send + Sync + 'static,
    {
        self.register_component(name, move || async move { check() }).await;
    }

    /// Unregister a component
    pub async fn unregister_component(&self, name: &str) {
        self.components.write().await.remove(name);
        info!("Unregistered health check component: {}", name);
    }

    /// Check if cached result is still valid
    async fn get_cached(&self) -> Option<HealthStatus> {
        let cache = self.cache.read().await;
        if let Some((status, timestamp)) = cache.as_ref() {
            if timestamp.elapsed() < self.cache_ttl {
                return Some(status.clone());
            }
        }
        None
    }

    /// Perform health check on all registered components
    pub async fn check(&self) -> HealthStatus {
        // Check cache first
        if let Some(cached) = self.get_cached().await {
            return cached;
        }

        let start = Instant::now();
        let components = self.components.read().await;
        let mut component_healths = Vec::new();
        let mut overall_status = HealthState::Healthy;

        for (name, check_fn) in components.iter() {
            let check_start = Instant::now();
            let result = check_fn().await;
            let response_time = check_start.elapsed().as_millis() as u64;

            let status = result.status();
            overall_status = overall_status.merge(status);

            component_healths.push(ComponentHealth {
                name: name.clone(),
                status,
                message: result.message(),
                last_check: SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                response_time_ms: response_time,
                details: None,
            });

            match status {
                HealthState::Healthy => {
                    crate::set_gauge!(
                        "vigilnet_health_component_status",
                        1.0,
                        "component" => name.as_str(),
                        "status" => "healthy"
                    );
                }
                HealthState::Degraded => {
                    crate::set_gauge!(
                        "vigilnet_health_component_status",
                        0.5,
                        "component" => name.as_str(),
                        "status" => "degraded"
                    );
                    warn!("Component {} is degraded: {}", name, result.message());
                }
                HealthState::Unhealthy => {
                    crate::set_gauge!(
                        "vigilnet_health_component_status",
                        0.0,
                        "component" => name.as_str(),
                        "status" => "unhealthy"
                    );
                    error!("Component {} is unhealthy: {}", name, result.message());
                }
            }
        }

        let status = HealthStatus {
            status: overall_status,
            version: VERSION.to_string(),
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            uptime_secs: self.started_at.elapsed().as_secs(),
            components: component_healths,
            metadata: HashMap::new(),
        };

        // Update cache
        *self.cache.write().await = Some((status.clone(), Instant::now()));

        // Record metrics
        let total_time = start.elapsed().as_millis() as u64;
        crate::record_histogram!(
            "vigilnet_health_check_duration_ms",
            total_time as f64
        );

        status
    }

    /// Quick liveness check
    pub async fn is_alive(&self) -> bool {
        // System is alive if we can acquire the lock
        let _ = self.components.read().await;
        true
    }

    /// Readiness check - all components healthy
    pub async fn is_ready(&self) -> bool {
        let status = self.check().await;
        status.status != HealthState::Unhealthy
    }

    /// Get uptime
    pub fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Get health status as JSON string
    pub async fn to_json(&self) -> String {
        let status = self.check().await;
        serde_json::to_string(&status).unwrap_or_else(|_| "{\"error\": \"serialization failed\"}".to_string())
    }

    /// Add metadata to health status
    pub async fn add_metadata(&self, key: &str, value: &str) {
        if let Some((ref mut status, _)) = *self.cache.write().await {
            status.metadata.insert(key.to_string(), value.to_string());
        }
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Standard health check implementations
pub mod checks {
    use super::*;

    /// Create a simple healthy check
    pub fn healthy() -> HealthCheckResult {
        HealthCheckResult::Healthy(None)
    }

    /// Create a healthy check with message
    pub fn healthy_with(message: &str) -> HealthCheckResult {
        HealthCheckResult::Healthy(Some(message.to_string()))
    }

    /// Create a degraded check
    pub fn degraded(message: &str) -> HealthCheckResult {
        HealthCheckResult::Degraded(message.to_string())
    }

    /// Create an unhealthy check
    pub fn unhealthy(message: &str) -> HealthCheckResult {
        HealthCheckResult::Unhealthy(message.to_string())
    }

    /// Check if a result is successful
    pub fn from_result<T, E: std::fmt::Display>(
        result: Result<T, E>,
    ) -> HealthCheckResult {
        match result {
            Ok(_) => healthy(),
            Err(e) => unhealthy(&e.to_string()),
        }
    }

    /// Check with timeout
    pub async fn with_timeout<F, Fut>(
        timeout: Duration,
        check: F,
    ) -> HealthCheckResult
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = HealthCheckResult>,
    {
        match tokio::time::timeout(timeout, check()).await {
            Ok(result) => result,
            Err(_) => degraded("Health check timed out"),
        }
    }
}

/// Health check endpoint handler
pub struct HealthEndpoint {
    checker: Arc<HealthChecker>,
}

impl HealthEndpoint {
    /// Create new health endpoint
    pub fn new(checker: Arc<HealthChecker>) -> Self {
        Self { checker }
    }

    /// Handle health check request
    pub async fn handle_health(&self) -> (u16, String) {
        let status = self.checker.check().await;
        let http_status = status.status.http_status();
        let body = serde_json::to_string(&status).unwrap_or_default();
        (http_status, body)
    }

    /// Handle liveness check
    pub async fn handle_liveness(&self) -> (u16, String) {
        if self.checker.is_alive().await {
            (200, r#"{"status":"alive"}"#.to_string())
        } else {
            (503, r#"{"status":"dead"}"#.to_string())
        }
    }

    /// Handle readiness check
    pub async fn handle_readiness(&self) -> (u16, String) {
        if self.checker.is_ready().await {
            (200, r#"{"status":"ready"}"#.to_string())
        } else {
            (503, r#"{"status":"not ready"}"#.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_checker() {
        let checker = HealthChecker::new();

        checker
            .register_sync_check("test", || checks::healthy())
            .await;

        let status = checker.check().await;
        assert_eq!(status.status, HealthState::Healthy);
        assert_eq!(status.components.len(), 1);
        assert_eq!(status.components[0].status, HealthState::Healthy);
    }

    #[tokio::test]
    async fn test_health_states() {
        let checker = HealthChecker::new();

        checker
            .register_sync_check("healthy", || checks::healthy())
            .await;
        checker
            .register_sync_check("degraded", || checks::degraded("slow response"))
            .await;

        let status = checker.check().await;
        assert_eq!(status.status, HealthState::Degraded);
    }

    #[tokio::test]
    async fn test_unhealthy_propagation() {
        let checker = HealthChecker::new();

        checker
            .register_sync_check("healthy", || checks::healthy())
            .await;
        checker
            .register_sync_check("unhealthy", || checks::unhealthy("critical error"))
            .await;

        let status = checker.check().await;
        assert_eq!(status.status, HealthState::Unhealthy);
    }

    #[test]
    fn test_health_state_merge() {
        assert_eq!(
            HealthState::Healthy.merge(HealthState::Healthy),
            HealthState::Healthy
        );
        assert_eq!(
            HealthState::Healthy.merge(HealthState::Degraded),
            HealthState::Degraded
        );
        assert_eq!(
            HealthState::Healthy.merge(HealthState::Unhealthy),
            HealthState::Unhealthy
        );
        assert_eq!(
            HealthState::Degraded.merge(HealthState::Healthy),
            HealthState::Degraded
        );
        assert_eq!(
            HealthState::Unhealthy.merge(HealthState::Healthy),
            HealthState::Unhealthy
        );
    }

    #[tokio::test]
    async fn test_liveness_readiness() {
        let checker = Arc::new(HealthChecker::new());
        let endpoint = HealthEndpoint::new(checker.clone());

        assert!(checker.is_alive().await);

        let (status, _) = endpoint.handle_liveness().await;
        assert_eq!(status, 200);
    }

    #[tokio::test]
    async fn test_cache() {
        let checker = HealthChecker::new().with_cache_ttl(Duration::from_secs(60));

        checker
            .register_sync_check("test", || checks::healthy())
            .await;

        let status1 = checker.check().await;
        let status2 = checker.check().await;

        // Should return cached result
        assert_eq!(status1.timestamp, status2.timestamp);
    }
}
