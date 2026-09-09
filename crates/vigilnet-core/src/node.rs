//! VigilNet Node
//!
//! Main node state machine and lifecycle management.

use crate::config::{AgentConfig, Config};
use crate::error::{Error, Result};
use crate::swarm::{SwarmCommand, SwarmNotification, VigilNetSwarm};
use libp2p::{Multiaddr, PeerId};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, instrument, trace, warn, Span};
use tracing_futures::Instrument;

#[cfg(feature = "agent")]
use vigilnet_agent_core::{
    Agent, AgentBuilder, AgentId, ConnectionPool, ConnectionPoolConfig, PreKeyBundle,
};

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
    /// Whether E2EE is enabled
    pub e2ee_active: bool,
    /// Whether agent network is enabled
    pub agent_active: bool,
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
    /// Agent (if enabled)
    #[cfg(feature = "agent")]
    agent: Option<Agent>,
}

impl Node {
    /// Create a new node with the given configuration
    #[instrument(skip(config), level = "info", fields(version = crate::VERSION))]
    pub fn new(config: Config) -> Self {
        let span = Span::current();
        trace!(parent: &span, "Creating new VigilNet node");

        let node = Self {
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
            #[cfg(feature = "agent")]
            agent: None,
        };

        info!("VigilNet node created");
        debug!(agent_feature_enabled = cfg!(feature = "agent"), "Node configuration");

        node
    }

    /// Create a node with default configuration
    pub fn with_defaults() -> Self {
        Self::new(Config::default())
    }

    /// Get the current node state
    #[instrument(skip(self), level = "trace")]
    pub async fn state(&self) -> NodeState {
        let state = self.inner.state.read().await.clone();
        trace!(?state, "Retrieved node state");
        state
    }

    /// Get current node statistics
    #[instrument(skip(self), level = "debug")]
    pub async fn stats(&self) -> NodeStats {
        let mut stats = self.inner.stats.read().await.clone();

        if let Some(started) = *self.inner.started_at.read().await {
            stats.uptime_secs = started.elapsed().as_secs();
        }

        stats.peer_count = self.inner.peers.read().await.len();

        debug!(
            peer_count = stats.peer_count,
            circuit_count = stats.circuit_count,
            uptime_secs = stats.uptime_secs,
            "Retrieved node statistics"
        );

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
    #[instrument(skip(self), level = "info")]
    pub async fn start(&mut self) -> Result<()> {
        trace!("Acquiring state lock for start operation");
        {
            let mut state = self.inner.state.write().await;
            if *state != NodeState::Stopped {
                warn!("Node start requested but node is not in Stopped state");
                return Err(Error::AlreadyRunning);
            }
            *state = NodeState::Starting;
            info!("Node state transitioned to Starting");
        }

        info!("Starting VigilNet node...");

        // Initialize agent if enabled
        #[cfg(feature = "agent")]
        if self.config.agent.enabled {
            info!("Agent feature enabled, initializing agent network...");
            self.initialize_agent().await?;
        } else {
            debug!("Agent feature disabled, skipping initialization");
        }

        // Create command and notification channels
        let (cmd_tx, cmd_rx) = mpsc::channel::<SwarmCommand>(32);
        let (notify_tx, mut notify_rx) = mpsc::channel::<SwarmNotification>(32);

        // Create the swarm
        let mut swarm = VigilNetSwarm::new(&self.config, cmd_rx, notify_tx)?;
        
        // Update stats with E2EE status
        self.inner.stats.write().await.e2ee_active = swarm.is_e2ee_enabled();
        
        // Local peer ID
        let local_peer_id = swarm.local_peer_id();
        info!("Local peer ID: {}", local_peer_id);
        *self.inner.local_peer_id.write().await = Some(local_peer_id);

        // Smart Relay Logic
        let mut relay_enabled = self.config.relay.enabled;
        if self.config.relay.smart_mode && !relay_enabled {
            if self.config.network.listen_addrs.iter().any(|a| a.contains("0.0.0.0")) {
                info!("Smart Relay: Public listener detected. Auto-enabling Relay Mode.");
                relay_enabled = true;
            }
        }

        self.inner.stats.write().await.relay_active = relay_enabled;
        self.inner.stats.write().await.agent_active = self.config.agent.enabled;

        debug!(relay_enabled, "Relay configuration applied");

        // Start listening
        trace!("Initiating swarm listening");
        swarm.start_listening(&self.config).await?;
        info!("Swarm listening started");

        // Store command sender
        self.swarm_cmd_tx = Some(cmd_tx);
        
        // Start the swarm event loop in a separate task
        let swarm_handle = tokio::spawn(async move {
            swarm.run().await;
        });
        self.swarm_handle = Some(swarm_handle);

        // Start notification handler
        let inner = Arc::clone(&self.inner);
        let notify_span = tracing::info_span!("notification_handler");
        let notify_handle = tokio::spawn(async move {
            while let Some(notification) = notify_rx.recv().await {
                match notification {
                    SwarmNotification::PeerConnected(peer_id) => {
                        info!(peer_id = %peer_id, "Peer connected");
                        inner.peers.write().await.push(peer_id);
                    }
                    SwarmNotification::PeerDisconnected(peer_id) => {
                        info!(peer_id = %peer_id, "Peer disconnected");
                        inner.peers.write().await.retain(|p| p != &peer_id);
                    }
                    SwarmNotification::Listening(addr) => {
                        info!(address = %addr, "Now listening on address");
                    }
                    SwarmNotification::CircuitBuilt(circuit_id) => {
                        info!(circuit_id = %circuit_id, "Circuit built successfully");
                        inner.stats.write().await.circuit_count += 1;
                    }
                    SwarmNotification::Error(e) => {
                        error!(error = %e, "Swarm error occurred");
                    }
                }
            }
            trace!("Notification handler loop ended");
        }.instrument(notify_span));
        self.notify_handle = Some(notify_handle);
        debug!("Notification handler task spawned");

        // Mark as running
        *self.inner.state.write().await = NodeState::Running;
        *self.inner.started_at.write().await = Some(Instant::now());

        info!(
            local_peer_id = ?self.inner.local_peer_id.read().await,
            relay_enabled,
            agent_enabled = self.config.agent.enabled,
            "VigilNet node started successfully"
        );
        Ok(())
    }

    /// Initialize agent network
    #[cfg(feature = "agent")]
    #[instrument(skip(self), level = "info")]
    async fn initialize_agent(&mut self) -> Result<()> {
        info!("Initializing agent network...");

        let pool_config = ConnectionPoolConfig {
            max_connections: self.config.agent.pool_size,
            connect_timeout: std::time::Duration::from_secs(10),
            idle_timeout: std::time::Duration::from_secs(300),
        };

        trace!("Building agent with configuration");
        let mut agent = AgentBuilder::new()
            .name(&self.config.agent.name)
            .capabilities(self.config.agent.capabilities.clone())
            .model_type(&self.config.agent.model_type)
            .connection_pool_config(pool_config)
            .enable_e2ee()
            .build()
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to build agent");
                Error::Agent(e.to_string())
            })?;

        info!(agent_id = %agent.id(), "Agent initialized successfully");
        self.agent = Some(agent);

        Ok(())
    }

    /// Get agent (if available)
    #[cfg(feature = "agent")]
    pub fn agent(&self) -> Option<&Agent> {
        self.agent.as_ref()
    }

    /// Get agent_mut (if available)
    #[cfg(feature = "agent")]
    pub fn agent_mut(&mut self) -> Option<&mut Agent> {
        self.agent.as_mut()
    }

    /// Create E2EE session with a peer
    #[cfg(feature = "agent")]
    pub async fn create_agent_session(&mut self, peer_id: &AgentId, bundle: &PreKeyBundle) -> Result<()> {
        if let Some(ref mut agent) = self.agent {
            agent.create_session(peer_id, bundle)
                .map_err(|e| Error::E2EE(e.to_string()))
        } else {
            Err(Error::Agent("Agent not initialized".into()))
        }
    }

    /// Stop the node
    #[instrument(skip(self), level = "info")]
    pub async fn stop(&mut self) -> Result<()> {
        trace!("Acquiring state lock for stop operation");
        {
            let state = self.inner.state.read().await;
            if *state != NodeState::Running {
                warn!(current_state = ?state, "Stop requested but node is not running");
                return Err(Error::NotRunning);
            }
        }

        *self.inner.state.write().await = NodeState::Stopping;
        info!("Stopping VigilNet node...");

        // Send shutdown command to swarm
        if let Some(tx) = &self.swarm_cmd_tx {
            trace!("Sending shutdown command to swarm");
            if let Err(e) = tx.send(SwarmCommand::Shutdown).await {
                error!(error = %e, "Failed to send shutdown command");
            } else {
                debug!("Shutdown command sent to swarm");
            }
        } else {
            warn!("No swarm command channel available");
        }

        // Wait for swarm to stop
        if let Some(handle) = self.swarm_handle.take() {
            trace!("Awaiting swarm task completion");
            if let Err(e) = handle.await {
                error!(error = %e, "Error awaiting swarm task");
            } else {
                debug!("Swarm task stopped successfully");
            }
        }

        // Abort notification handler
        if let Some(handle) = self.notify_handle.take() {
            trace!("Aborting notification handler");
            handle.abort();
            debug!("Notification handler aborted");
        }

        // Clear state
        let cleared_peers = self.inner.peers.write().await.len();
        self.swarm_cmd_tx = None;
        self.inner.peers.write().await.clear();
        *self.inner.local_peer_id.write().await = None;
        *self.inner.started_at.write().await = None;
        *self.inner.state.write().await = NodeState::Stopped;

        info!(cleared_peers, "VigilNet node stopped successfully");
        Ok(())
    }

    /// Check if the node is running
    #[instrument(skip(self), level = "trace")]
    pub async fn is_running(&self) -> bool {
        let running = *self.inner.state.read().await == NodeState::Running;
        trace!(is_running = running, "Node running status checked");
        running
    }

    /// Build a new anonymous circuit
    #[instrument(skip(self), level = "info")]
    pub async fn build_circuit(&self) -> Result<u32> {
        trace!("Requesting circuit build");
        if let Some(tx) = &self.swarm_cmd_tx {
            let (resp_tx, mut resp_rx) = mpsc::channel(1);
            tx.send(SwarmCommand::BuildCircuit(resp_tx)).await
                .map_err(|e| {
                    error!(error = %e, "Failed to send build circuit command");
                    Error::NotRunning
                })?;

            trace!("Awaiting circuit build response");
            match resp_rx.recv().await {
                Some(Ok(id)) => {
                    info!(circuit_id = id, "Circuit built successfully");
                    Ok(id)
                }
                Some(Err(e)) => {
                    error!(error = %e, "Circuit build failed");
                    Err(e)
                }
                None => {
                    error!("Swarm channel closed unexpectedly");
                    Err(Error::Internal("Swarm channel closed".into()))
                }
            }
        } else {
            warn!("Cannot build circuit: swarm not running");
            Err(Error::NotRunning)
        }
    }

    /// Send data through a circuit
    #[instrument(skip(self, data), level = "debug", fields(data_len = data.len()))]
    pub async fn send_data(&self, circuit_id: u32, data: Vec<u8>) -> Result<()> {
        trace!(circuit_id, "Sending data through circuit");
        if let Some(tx) = &self.swarm_cmd_tx {
            let (resp_tx, mut resp_rx) = mpsc::channel(1);
            tx.send(SwarmCommand::SendData(circuit_id, data, resp_tx)).await
                .map_err(|e| {
                    error!(error = %e, "Failed to send data command");
                    Error::NotRunning
                })?;

            match resp_rx.recv().await {
                Some(Ok(())) => {
                    trace!(circuit_id, "Data sent successfully");
                    Ok(())
                }
                Some(Err(e)) => {
                    error!(circuit_id, error = %e, "Data send failed");
                    Err(e)
                }
                None => {
                    error!("Swarm channel closed unexpectedly");
                    Err(Error::Internal("Swarm channel closed".into()))
                }
            }
        } else {
            warn!("Cannot send data: swarm not running");
            Err(Error::NotRunning)
        }
    }

    /// Dial a peer
    #[instrument(skip(self, addr), level = "info")]
    pub async fn dial(&self, addr: Multiaddr) -> Result<()> {
        info!(address = %addr, "Dialing peer");
        if let Some(tx) = &self.swarm_cmd_tx {
            tx.send(SwarmCommand::Dial(addr)).await
                .map_err(|e| {
                    error!(error = %e, "Failed to send dial command");
                    Error::NotRunning
                })?;
            debug!("Dial command sent successfully");
            Ok(())
        } else {
            warn!("Cannot dial: swarm not running");
            Err(Error::NotRunning)
        }
    }

    /// Add a bootstrap peer
    #[instrument(skip(self, addr), level = "info")]
    pub async fn add_bootstrap_peer(&self, peer_id: PeerId, addr: Multiaddr) -> Result<()> {
        info!(peer_id = %peer_id, address = %addr, "Adding bootstrap peer");
        if let Some(tx) = &self.swarm_cmd_tx {
            tx.send(SwarmCommand::AddBootstrapPeer(peer_id, addr)).await
                .map_err(|e| {
                    error!(error = %e, "Failed to send add bootstrap peer command");
                    Error::NotRunning
                })?;
            debug!("Bootstrap peer added successfully");
            Ok(())
        } else {
            warn!("Cannot add bootstrap peer: swarm not running");
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
