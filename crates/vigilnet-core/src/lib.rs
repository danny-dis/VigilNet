//! VigilNet Core
//!
//! Main orchestration crate for the VigilNet privacy network.
//! Handles node lifecycle, configuration, and coordinates all subsystems.
//!
//! # Features
//!
//! - `agent`: Enable agent network integration with E2EE support
//!
//! # Example
//!
//! ```ignore
//! use vigilnet_core::{Node, Config};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = Config::default();
//!     let mut node = Node::new(config);
//!     node.start().await?;
//!
//!     // ... use node
//!
//!     node.stop().await?;
//!     Ok(())
//! }
//! ```

use tracing::{debug, info, instrument, trace, warn};

pub mod config;
pub mod error;
pub mod health;
pub mod instrumentation;
pub mod metrics;
pub mod node;
pub mod swarm;

pub use config::{
    AgentConfig, Config, DnsMode, IdentityConfig, NetworkConfig, PathStrategy, PrivacyConfig,
    RelayConfig, TunConfig,
};
pub use error::{Error, Result};
pub use health::{
    checks as health_checks, ComponentHealth, HealthCheckResult, HealthChecker, HealthEndpoint,
    HealthState, HealthStatus,
};
pub use instrumentation::{
    count_event, increment_counter, instrument_async, instrument_fn, record_histogram, set_gauge,
    time_operation, ManualTimer, ScopedTimer,
};
pub use metrics::{
    global_metrics, init_global_metrics, AgentMetrics, AgentSnapshot, ConnectionMetrics,
    ConnectionSnapshot, CryptoMetrics, CryptoSnapshot, ErrorCounters, ErrorSnapshot,
    LatencyHistograms, MetricLabels, Metrics, MetricsSnapshot, NetworkMetrics, NetworkSnapshot,
    SystemMetrics, SystemSnapshot, Timer,
};
pub use node::{Node, NodeState, NodeStats};
pub use swarm::{SwarmCommand, SwarmNotification, VigilNetSwarm};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize tracing for VigilNet core
#[instrument(level = "info")]
pub fn init_tracing() {
    trace!("Initializing VigilNet core tracing");
    info!(version = VERSION, "VigilNet Core initialized");
    debug!("Tracing subsystem active");
}

/// Log system configuration summary
#[instrument(level = "debug", skip(config))]
pub fn log_config_summary(config: &Config) {
    trace!("Logging configuration summary");
    debug!(
        agent_enabled = config.agent.enabled,
        relay_enabled = config.relay.enabled,
        "Configuration summary"
    );
}
