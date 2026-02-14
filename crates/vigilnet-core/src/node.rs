//! VigilNet Node
//!
//! Main node state machine and lifecycle management.

use crate::swarm::{SwarmCommand, SwarmNotification, VigilNetSwarm};
use crate::{Config, Error, Result};
use libp2p::PeerId;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

/// Node state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeState {
    /// Node is stopped
    Stopped,
    /// Node is starting up
    Starting,
    /// Node is running and connected to the network
    Running,
    /// Node is shutting down
    Stopping,
}

/// Statistics about the node
#[derive(Debug, Clone, Default)]
pub struct NodeStats {
    /// Number of known peers
    pub peer_count: usize,
    /// Number of active circuits
    pub circuit_count: usize,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Whether relay mode is active
    pub relay_active: bool,
}

/// Inner state that can be shared across tasks
struct NodeInner {
    /// Current state
    state: RwLock<NodeState>,
    /// Node statistics
    stats: RwLock<NodeStats>,
    /// Connected peers
    peers: RwLock<Vec<PeerId>>,
    /// Start time (for uptime calculation)
    started_at: RwLock<Option<Instant>>,
    /// Local peer ID
    local_peer_id: RwLock<Option<PeerId>>,
}

/// A VigilNet node
pub struct Node {
    /// Node configuration
    config: Config,
    /// Shared inner state
    inner: Arc<NodeInner>,
    /// Command sender for the swarm
    swarm_cmd_tx: Option<mpsc::Sender<SwarmCommand>>,
    /// Swarm task handle
    swarm_handle: Option<JoinHandle<()>>,
    /// Notification receiver task handle
    notify_handle: Option<JoinHandle<()>>,
}

impl Node {
    /// Create a new node with the given configuration
    pub fn new(config: Config) -> Self {
        Self {
            config,
            inner: Arc::new(NodeInner {
                state: RwLock::new(NodeState::Stopped),
                stats: RwLock::new(NodeStats::default()),
                peers: RwLock::new(Vec::new()),
                started_at: RwLock::new(None),
                local_peer_id: RwLock::new(None),
            }),
            swarm_cmd_tx: None,
            swarm_handle: None,
            notify_handle: None,
        }
    }

    /// Create a node with default configuration
    pub fn with_defaults() -> Self {
        Self::new(Config::default())
    }

    /// Get the current node state
    pub async fn state(&self) -> NodeState {
        self.inner.state.read().await.clone()
    }

    /// Get current node statistics
    pub async fn stats(&self) -> NodeStats {
        let mut stats = self.inner.stats.read().await.clone();
        
        // Update uptime
        if let Some(started) = *self.inner.started_at.read().await {
            stats.uptime_secs = started.elapsed().as_secs();
        }
        
        // Update peer count
        stats.peer_count = self.inner.peers.read().await.len();
        
        stats
    }

    /// Get the node configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get the local peer ID (None if not started)
    pub async fn local_peer_id(&self) -> Option<PeerId> {
        *self.inner.local_peer_id.read().await
    }

    /// Get the list of connected peers
    pub async fn peers(&self) -> Vec<PeerId> {
        if let Some(tx) = &self.swarm_cmd_tx {
            let (resp_tx, mut resp_rx) = mpsc::channel(1);
            if tx.send(SwarmCommand::GetPeers(resp_tx)).await.is_ok() {
                if let Some(peers) = resp_rx.recv().await {
                    return peers;
                }
            }
        }
        self.inner.peers.read().await.clone()
    }

    /// Start the node
    pub async fn start(&mut self) -> Result<()> {
        {
            let mut state = self.inner.state.write().await;
            if *state != NodeState::Stopped {
                return Err(Error::AlreadyRunning);
            }
            *state = NodeState::Starting;
        }
        
        info!("Starting VigilNet node...");

        // Create command and notification channels
        let (cmd_tx, cmd_rx) = mpsc::channel::<SwarmCommand>(32);
        let (notify_tx, mut notify_rx) = mpsc::channel::<SwarmNotification>(32);

        // Create the swarm
        let mut swarm = VigilNetSwarm::new(&self.config, cmd_rx, notify_tx)?;
        // Local peer ID
        let local_peer_id = swarm.local_peer_id();
        info!("Local peer ID: {}", local_peer_id);
        *self.inner.local_peer_id.write().await = Some(local_peer_id);

        // Smart Relay Logic
        let mut relay_enabled = self.config.relay.enabled;
        if self.config.relay.smart_mode && !relay_enabled {
            // Simplified check: if we are listening on all interfaces, assume we might be reachable
            // In reality, we'd check STUN/UPnP result here.
            if self.config.network.listen_addrs.iter().any(|a| a.contains("0.0.0.0")) {
                info!("Smart Relay: Public listener detected. Auto-enabling Relay Mode.");
                relay_enabled = true;
                // TODO: Update swarm behavior to allow relaying (e.g. enable circuit handling)
                // self.swarm.enable_relay(); 
            }
        }
        
        self.inner.stats.write().await.relay_active = relay_enabled;

        // Start listening
        swarm.start_listening(&self.config).await?;

        // Store command sender
        self.swarm_cmd_tx = Some(cmd_tx);
        
        // Start the swarm event loop in a separate task
        let swarm_handle = tokio::spawn(async move {
            swarm.run().await;
        });
        self.swarm_handle = Some(swarm_handle);

        // Start notification handler
        let inner = Arc::clone(&self.inner);
        let notify_handle = tokio::spawn(async move {
            while let Some(notification) = notify_rx.recv().await {
                match notification {
                    SwarmNotification::PeerConnected(peer_id) => {
                        info!("Peer connected: {}", peer_id);
                        inner.peers.write().await.push(peer_id);
                    }
                    SwarmNotification::PeerDisconnected(peer_id) => {
                        info!("Peer disconnected: {}", peer_id);
                        inner.peers.write().await.retain(|p| p != &peer_id);
                    }
                    SwarmNotification::Listening(addr) => {
                        debug!("Now listening on: {}", addr);
                    }
                    SwarmNotification::Error(e) => {
                        error!("Swarm error: {}", e);
                    }
                }
            }
        });
        self.notify_handle = Some(notify_handle);

        // Mark as running
        *self.inner.state.write().await = NodeState::Running;
        *self.inner.started_at.write().await = Some(Instant::now());
        
        info!("VigilNet node started successfully");
        Ok(())
    }

    /// Stop the node
    pub async fn stop(&mut self) -> Result<()> {
        {
            let state = self.inner.state.read().await;
            if *state != NodeState::Running {
                return Err(Error::NotRunning);
            }
        }

        *self.inner.state.write().await = NodeState::Stopping;
        warn!("Stopping VigilNet node...");

        // Send shutdown command to swarm
        if let Some(tx) = &self.swarm_cmd_tx {
            let _ = tx.send(SwarmCommand::Shutdown).await;
        }

        // Wait for swarm to stop
        if let Some(handle) = self.swarm_handle.take() {
            let _ = handle.await;
        }

        // Abort notification handler
        if let Some(handle) = self.notify_handle.take() {
            handle.abort();
        }

        // Clear state
        self.swarm_cmd_tx = None;
        self.inner.peers.write().await.clear();
        *self.inner.local_peer_id.write().await = None;
        *self.inner.started_at.write().await = None;
        *self.inner.state.write().await = NodeState::Stopped;
        
        info!("VigilNet node stopped");
        Ok(())
    }

    /// Check if the node is running
    pub async fn is_running(&self) -> bool {
        *self.inner.state.read().await == NodeState::Running
    }

    /// Build a new anonymous circuit
    pub async fn build_circuit(&self) -> Result<u32> {
        if let Some(tx) = &self.swarm_cmd_tx {
            let (resp_tx, mut resp_rx) = mpsc::channel(1);
            tx.send(SwarmCommand::BuildCircuit(resp_tx)).await
                .map_err(|_| Error::NotRunning)?;
            
            // Wait for circuit ID or error
            match resp_rx.recv().await {
                Some(Ok(id)) => Ok(id),
                Some(Err(e)) => Err(e),
                None => Err(Error::Internal("Swarm channel closed".into())),
            }
        } else {
            Err(Error::NotRunning)
        }
    }

    /// Send data through a circuit
    pub async fn send_data(&self, circuit_id: u32, data: Vec<u8>) -> Result<()> {
        if let Some(tx) = &self.swarm_cmd_tx {
            let (resp_tx, mut resp_rx) = mpsc::channel(1);
            tx.send(SwarmCommand::SendData(circuit_id, data, resp_tx)).await
                .map_err(|_| Error::NotRunning)?;
            
            match resp_rx.recv().await {
                Some(Ok(())) => Ok(()),
                Some(Err(e)) => Err(e),
                None => Err(Error::Internal("Swarm channel closed".into())),
            }
        } else {
            Err(Error::NotRunning)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_node_create() {
        let node = Node::with_defaults();
        assert_eq!(node.state().await, NodeState::Stopped);
    }
}
