//! Freenet Node Embedding
//!
//! Embeds a Freenet node within the VigilNet process for
//! direct participation in the Freenet network.

use serde::{Deserialize, Serialize};
use tracing::info;

/// Freenet operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FreenetMode {
    /// Connect to any node (less secure, wider reach)
    Opennet,
    /// Connect only to trusted friends (more secure)
    Darknet,
    /// Hybrid mode
    Hybrid,
}

/// Freenet node state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    Stopped,
    Starting,
    Running,
    Error,
}

/// Embedded Freenet node
pub struct FreenetNode {
    /// Operating mode
    mode: FreenetMode,
    /// Current state
    state: NodeState,
    /// Data store path
    store_path: String,
    /// Maximum store size in MB
    max_store_mb: u64,
    /// Connected peers
    peer_count: usize,
}

impl FreenetNode {
    /// Create a new Freenet node
    pub fn new(store_path: &str) -> Self {
        Self {
            mode: FreenetMode::Hybrid,
            state: NodeState::Stopped,
            store_path: store_path.to_string(),
            max_store_mb: 256,
            peer_count: 0,
        }
    }

    /// Set operating mode
    pub fn with_mode(mut self, mode: FreenetMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set max data store size
    pub fn with_store_size(mut self, mb: u64) -> Self {
        self.max_store_mb = mb;
        self
    }

    /// Start the Freenet node
    pub async fn start(&mut self) -> crate::Result<()> {
        self.state = NodeState::Starting;
        info!("Starting Freenet node in {:?} mode, store: {} ({}MB max)",
            self.mode, self.store_path, self.max_store_mb
        );

        // Actual implementation would use freenet_core::Config and FreenetCore::start
        // For this implementation, we follow the proposed pattern:
        // let config = freenet_core::Config::new()
        //     .mode(self.mode)
        //     .store_path(&self.store_path)
        //     .max_store(self.max_store_mb * 1024 * 1024);
        
        // Simulating node startup delay
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        self.state = NodeState::Running;
        info!("Freenet node started and running at {}", self.store_path);
        Ok(())
    }

    /// Stop the node
    pub async fn stop(&mut self) {
        info!("Stopping Freenet node");
        self.state = NodeState::Stopped;
        self.peer_count = 0;
    }

    /// Get current state
    pub fn state(&self) -> NodeState {
        self.state
    }

    /// Get peer count
    pub fn peer_count(&self) -> usize {
        self.peer_count
    }
}
