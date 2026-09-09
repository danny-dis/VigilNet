use crate::ble_mesh::BleMesh;
use crate::dtn_store::DtnStore;
use crate::meshtastic_bridge::MeshtasticBridge;
use anyhow::Result as AnyhowResult;
use bytes::Bytes;
use dashmap::DashMap;
use futures::StreamExt;
use parking_lot::RwLock;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration, MissedTickBehavior};
use tracing::{debug, error, info, instrument, warn};

pub use ble_mesh::{BleConfig, BleDiscovery};
pub use dtn_store::{DtnMessage, DtnStoreConfig};
pub use meshtastic_bridge::MeshtasticConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkType {
    Quic,
    Tcp,
    Ble,
    Meshtastic,
    Offline,
}

impl NetworkType {
    pub fn priority(&self) -> u8 {
        match self {
            NetworkType::Quic => 4,
            NetworkType::Tcp => 3,
            NetworkType::Ble => 2,
            NetworkType::Meshtastic => 1,
            NetworkType::Offline => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::Disconnected
    }
}

#[derive(Debug, Clone)]
pub struct NetworkStatus {
    pub network_type: NetworkType,
    pub connection_state: ConnectionState,
    pub latency_ms: Option<u64>,
    pub bandwidth_mbps: Option<f64>,
    pub available_networks: Vec<NetworkType>,
}

impl Default for NetworkStatus {
    fn default() -> Self {
        Self {
            network_type: NetworkType::Offline,
            connection_state: ConnectionState::Disconnected,
            latency_ms: None,
            bandwidth_mbps: None,
            available_networks: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum MeshMessage {
    Data {
        payload: Bytes,
        priority: u8,
        source: String,
        destination: String,
    },
    Control {
        command: MeshCommand,
    },
    HealthCheck {
        agent_id: String,
    },
}

#[derive(Debug, Clone)]
pub enum MeshCommand {
    SwitchNetwork(NetworkType),
    ForceReconnect,
    EnableFallback,
    DisableFallback,
    GetStatus,
}

#[derive(Debug, Clone)]
pub enum FallbackEvent {
    NetworkChanged(NetworkType),
    ConnectionEstablished(NetworkType),
    ConnectionLost(NetworkType),
    MessageQueued(Vec<u8>),
    MessageDelivered(String),
    FallbackTriggered(NetworkType),
}

pub struct MeshFallbackConfig {
    pub enable_ble: bool,
    pub enable_meshtastic: bool,
    pub quic_endpoints: Vec<SocketAddr>,
    pub tcp_endpoints: Vec<SocketAddr>,
    pub meshtastic_config: Option<MeshtasticConfig>,
    pub ble_config: Option<BleConfig>,
    pub dtn_store_config: DtnStoreConfig,
    pub fallback_timeout: Duration,
    pub health_check_interval: Duration,
    pub max_queue_size: usize,
}

impl Default for MeshFallbackConfig {
    fn default() -> Self {
        Self {
            enable_ble: cfg!(target_os = "linux"),
            enable_meshtastic: true,
            quic_endpoints: Vec::new(),
            tcp_endpoints: Vec::new(),
            meshtastic_config: None,
            ble_config: None,
            dtn_store_config: DtnStoreConfig::default(),
            fallback_timeout: Duration::from_secs(30),
            health_check_interval: Duration::from_secs(10),
            max_queue_size: 10000,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MeshError {
    #[error("Network unavailable: {0}")]
    NetworkUnavailable(String),
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    #[error("Message send failed: {0}")]
    SendFailed(String),
    #[error("BLE error: {0}")]
    BleError(String),
    #[error("Meshtastic error: {0}")]
    MeshtasticError(String),
    #[error("DTN store error: {0}")]
    DtnError(String),
    #[error("All fallback paths exhausted")]
    AllPathsExhausted,
}

pub type MeshResult<T> = Result<T, MeshError>;

pub struct MeshFallback {
    config: MeshFallbackConfig,
    status: Arc<RwLock<NetworkStatus>>,
    message_queue: Arc<RwLock<VecDeque<(MeshMessage, u64)>>>,
    event_sender: mpsc::Sender<FallbackEvent>,
    event_receiver: Arc<RwLock<Option<mpsc::Receiver<FallbackEvent>>>>,
    dtn_store: Arc<RwLock<Option<DtnStore>>>,
    ble_mesh: Arc<RwLock<Option<BleMesh>>>,
    meshtastic_bridge: Arc<RwLock<Option<MeshtasticBridge>>>,
    agent_connections: Arc<DashMap<String, NetworkType>>,
    pending_messages: Arc<DashMap<String, (Vec<u8>, u8)>>,
}

impl MeshFallback {
    #[instrument(skip_all, name = "MeshFallback::new")]
    pub fn new(config: MeshFallbackConfig) -> AnyhowResult<Self> {
        let (event_sender, event_receiver) = mpsc::channel(100);
        
        let dtn_store = DtnStore::new(config.dtn_store_config.clone())?;

        Ok(Self {
            config,
            status: Arc::new(RwLock::new(NetworkStatus::default())),
            message_queue: Arc::new(RwLock::new(VecDeque::new())),
            event_sender,
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
            dtn_store: Arc::new(RwLock::new(Some(dtn_store))),
            ble_mesh: Arc::new(RwLock::new(None)),
            meshtastic_bridge: Arc::new(RwLock::new(None)),
            agent_connections: Arc::new(DashMap::new()),
            pending_messages: Arc::new(DashMap::new()),
        })
    }

    pub async fn initialize(&mut self) -> MeshResult<()> {
        info!("Initializing mesh fallback system");

        self.detect_available_networks().await;

        if self.config.enable_meshtastic {
            if let Some(ref meshtastic_config) = self.config.meshtastic_config {
                match MeshtasticBridge::new(meshtastic_config.clone()) {
                    Ok(bridge) => {
                        *self.meshtastic_bridge.write() = Some(bridge);
                        info!("Meshtastic bridge initialized");
                    }
                    Err(e) => {
                        warn!("Failed to initialize Meshtastic bridge: {}", e);
                    }
                }
            }
        }

        if self.config.enable_ble {
            if let Some(ref ble_config) = self.config.ble_config {
                match BleMesh::new(ble_config.clone()) {
                    Ok(ble) => {
                        *self.ble_mesh.write() = Some(ble);
                        info!("BLE mesh initialized");
                    }
                    Err(e) => {
                        warn!("Failed to initialize BLE mesh: {}", e);
                    }
                }
            }
        }

        self.attempt_connection().await?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn detect_available_networks(&mut self) {
        let mut available = Vec::new();

        if !self.config.quic_endpoints.is_empty() || !self.config.tcp_endpoints.is_empty() {
            available.push(NetworkType::Quic);
            available.push(NetworkType::Tcp);
        }

        if self.config.enable_ble {
            available.push(NetworkType::Ble);
        }

        if self.config.enable_meshtastic {
            available.push(NetworkType::Meshtastic);
        }

        let mut status = self.status.write();
        status.available_networks = available;
        
        info!(
            available_networks = ?status.available_networks,
            "Network detection complete"
        );
    }

    #[instrument(skip(self))]
    async fn attempt_connection(&mut self) -> MeshResult<()> {
        let available = {
            let status = self.status.read();
            status.available_networks.clone()
        };

        if available.is_empty() {
            return Err(MeshError::NetworkUnavailable("No networks available".to_string()));
        }

        let mut best_network = NetworkType::Offline;
        let mut best_priority = 0u8;

        for &network in &available {
            if network.priority() > best_priority {
                best_priority = network.priority();
                best_network = network;
            }
        }

        if best_network == NetworkType::Offline {
            return Err(MeshError::NetworkUnavailable("All networks unavailable".to_string()));
        }

        self.transition_to_network(best_network).await
    }

    async fn transition_to_network(&mut self, network: NetworkType) -> MeshResult<()> {
        let current = {
            let status = self.status.read();
            status.network_type
        };

        if current == network {
            return Ok(());
        }

        info!(from = ?current, to = ?network, "Transitioning network");

        {
            let mut status = self.status.write();
            status.connection_state = ConnectionState::Connecting;
        }

        let result = match network {
            NetworkType::Quic | NetworkType::Tcp => {
                self.connect_to_tcp_network(network).await
            }
            NetworkType::Ble => {
                self.connect_ble_mesh().await
            }
            NetworkType::Meshtastic => {
                self.connect_meshtastic().await
            }
            NetworkType::Offline => {
                Ok(())
            }
        };

        match result {
            Ok(()) => {
                {
                    let mut status = self.status.write();
                    status.network_type = network;
                    status.connection_state = ConnectionState::Connected;
                }

                let _ = self.event_sender
                    .send(FallbackEvent::ConnectionEstablished(network))
                    .await;

                info!(network = ?network, "Successfully connected to network");
                
                self.flush_pending_messages().await;

                Ok(())
            }
            Err(e) => {
                error!(network = ?network, error = %e, "Failed to connect to network");
                
                let _ = self.event_sender
                    .send(FallbackEvent::ConnectionLost(network))
                    .await;

                self.try_fallback().await
            }
        }
    }

    async fn connect_to_tcp_network(&self, _network: NetworkType) -> MeshResult<()> {
        if self.config.tcp_endpoints.is_empty() && self.config.quic_endpoints.is_empty() {
            return Err(MeshError::NetworkUnavailable("No endpoints configured".to_string()));
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
        
        Ok(())
    }

    async fn connect_ble_mesh(&self) -> MeshResult<()> {
        let ble = self.ble_mesh.read();
        if let Some(ref ble_mesh) = *ble {
            ble_mesh.connect().await
        } else {
            Err(MeshError::BleError("BLE not initialized".to_string()))
        }
    }

    async fn connect_meshtastic(&self) -> MeshResult<()> {
        let meshtastic = self.meshtastic_bridge.read();
        if let Some(ref bridge) = *meshtastic {
            bridge.connect().await
        } else {
            Err(MeshError::MeshtasticError("Meshtastic not initialized".to_string()))
        }
    }

    async fn try_fallback(&mut self) -> MeshResult<()> {
        let available = {
            let status = self.status.read();
            status.available_networks.clone()
        };

        let current = {
            let status = self.status.read();
            status.network_type
        };

        let mut fallback_order: Vec<NetworkType> = available
            .into_iter()
            .filter(|&n| n != current)
            .collect();

        fallback_order.sort_by(|a, b| b.priority().cmp(&a.priority()));

        for network in fallback_order {
            info!(trying = ?network, "Attempting fallback to network");
            
            let _ = self.event_sender
                .send(FallbackEvent::FallbackTriggered(network))
                .await;

            match self.transition_to_network(network).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!(network = ?network, error = %e, "Fallback failed, trying next");
                }
            }
        }

        {
            let mut status = self.status.write();
            status.network_type = NetworkType::Offline;
            status.connection_state = ConnectionState::Disconnected;
        }

        Err(MeshError::AllPathsExhausted)
    }

    pub async fn send_message(&self, payload: Vec<u8>, destination: String, priority: u8) -> MeshResult<()> {
        let message = MeshMessage::Data {
            payload: Bytes::from(payload.clone()),
            priority,
            source: String::new(),
            destination: destination.clone(),
        };

        {
            let status = self.status.read();
            if status.connection_state == ConnectionState::Connected {
                self.send_via_current_network(&payload, &destination).await?;
                return Ok(());
            }
        }

        self.queue_message(message).await;

        let _ = self.event_sender
            .send(FallbackEvent::MessageQueued(payload))
            .await;

        Ok(())
    }

    async fn send_via_current_network(&self, payload: &[u8], destination: &str) -> MeshResult<()> {
        let network = {
            let status = self.status.read();
            status.network_type
        };

        match network {
            NetworkType::Quic | NetworkType::Tcp => {
                debug!(dest = %destination, "Sending via TCP/QUIC");
            }
            NetworkType::Ble => {
                let ble = self.ble_mesh.read();
                if let Some(ref ble_mesh) = *ble {
                    ble_mesh.send(payload, destination).await?;
                }
            }
            NetworkType::Meshtastic => {
                let meshtastic = self.meshtastic_bridge.read();
                if let Some(ref bridge) = *meshtastic {
                    bridge.publish(destination, payload).await?;
                }
            }
            NetworkType::Offline => {
                return Err(MeshError::NetworkUnavailable("Offline".to_string()));
            }
        }

        Ok(())
    }

    async fn queue_message(&self, message: MeshMessage) {
        let mut queue = self.message_queue.write();

        if queue.len() >= self.config.max_queue_size {
            queue.pop_front();
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        queue.push_back((message, timestamp));

        if let Some(ref store) = *self.dtn_store.read() {
            if let MeshMessage::Data { payload, destination, .. } = message {
                let _ = store.store(&payload, &destination);
            }
        }
    }

    async fn flush_pending_messages(&mut self) {
        let messages: Vec<_> = {
            let mut queue = self.message_queue.write();
            queue.drain(..).collect()
        };

        for (message, _) in messages {
            if let MeshMessage::Data { payload, destination, .. } = message {
                if let Err(e) = self.send_via_current_network(&payload, &destination).await {
                    warn!(error = %e, "Failed to send pending message");
                    self.queue_message(MeshMessage::Data {
                        payload: Bytes::from(payload),
                        priority: 0,
                        source: String::new(),
                        destination,
                    }).await;
                }
            }
        }
    }

    pub fn get_status(&self) -> NetworkStatus {
        self.status.read().clone()
    }

    pub async fn handle_event(&mut self, event: FallbackEvent) {
        match event {
            FallbackEvent::ConnectionLost(network) => {
                warn!(network = ?network, "Connection lost, attempting fallback");
                if let Err(e) = self.try_fallback().await {
                    error!(error = %e, "All fallback paths exhausted");
                }
            }
            FallbackEvent::NetworkChanged(network) => {
                info!(network = ?network, "Network changed");
            }
            _ => {}
        }
    }

    pub async fn run(mut self) -> AnyhowResult<()> {
        let mut health_check = interval(self.config.health_check_interval);
        health_check.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let mut event_receiver = self.event_receiver.write().take();
        
        if let Some(ref mut store) = *self.dtn_store.write() {
            store.start_cleanup_task().await?;
        }

        if let Some(ref mut bridge) = *self.meshtastic_bridge.write() {
            bridge.start_listener().await?;
        }

        loop {
            tokio::select! {
                _ = health_check.tick() => {
                    self.health_check().await;
                }
                event = async {
                    if let Some(ref mut rx) = event_receiver {
                        rx.recv().await
                    } else {
                        None
                    }
                } => {
                    if let Some(evt) = event {
                        self.handle_event(evt).await;
                    }
                }
            }
        }
    }

    async fn health_check(&self) {
        let status = self.status.read();
        
        if status.connection_state == ConnectionState::Connected {
            debug!("Health check: connection alive");
        } else {
            debug!("Health check: no active connection");
        }
    }

    pub async fn shutdown(&mut self) -> AnyhowResult<()> {
        info!("Shutting down mesh fallback");

        if let Some(ref mut store) = *self.dtn_store.write() {
            store.flush()?;
        }

        if let Some(ref mut bridge) = *self.meshtastic_bridge.write() {
            bridge.disconnect().await?;
        }

        if let Some(ref mut ble) = *self.ble_mesh.write() {
            ble.shutdown().await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mesh_fallback_creation() -> AnyhowResult<()> {
        let config = MeshFallbackConfig::default();
        let _mesh = MeshFallback::new(config)?;
        Ok(())
    }

    #[tokio::test]
    async fn test_network_priority() {
        assert!(NetworkType::Quic.priority() > NetworkType::Tcp.priority());
        assert!(NetworkType::Tcp.priority() > NetworkType::Ble.priority());
        assert!(NetworkType::Ble.priority() > NetworkType::Meshtastic.priority());
        assert!(NetworkType::Meshtastic.priority() > NetworkType::Offline.priority());
    }
}
