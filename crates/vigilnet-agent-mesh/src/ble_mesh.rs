use crate::mesh_fallback::MeshError;
use crate::mesh_fallback::MeshResult;
use anyhow::Result as AnyhowResult;
use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, instrument, warn};

#[derive(Debug, Clone)]
pub struct BleConfig {
    pub device_name: String,
    pub service_uuid: String,
    pub characteristic_uuid: String,
    pub advertise_interval_ms: u16,
    pub scan_duration_secs: u16,
    pub max_connections: usize,
    pub tx_power: i8,
}

impl Default for BleConfig {
    fn default() -> Self {
        Self {
            device_name: "VigilNet-Agent".to_string(),
            service_uuid: "6e400001-b5a3-f393-e0a9-e50e24dcca9e".to_string(),
            characteristic_uuid: "6e400003-b5a3-f393-e0a9-e50e24dcca9e".to_string(),
            advertise_interval_ms: 160,
            scan_duration_secs: 10,
            max_connections: 5,
            tx_power: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BlePeer {
    pub id: String,
    pub address: String,
    pub name: Option<String>,
    pub rssi: i16,
    pub connected: bool,
    pub last_seen: u64,
}

impl BlePeer {
    pub fn new(address: String, name: Option<String>) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            id,
            address,
            name,
            rssi: 0,
            connected: false,
            last_seen,
        }
    }
}

pub trait BleDiscovery: Send + Sync {
    fn discover(&mut self) -> impl std::future::Future<Output = Vec<BlePeer>> + Send;
    fn connect(&mut self, peer: &BlePeer) -> impl std::future::Future<Output = MeshResult<()>> + Send;
    fn disconnect(&mut self, peer: &BlePeer) -> impl std::future::Future<Output = MeshResult<()>> + Send;
    fn send(&mut self, data: &[u8], peer_id: &str) -> impl std::future::Future<Output = MeshResult<()>> + Send;
    fn receive(&mut self) -> impl std::future::Future<Output = Option<(String, Vec<u8>)>> + Send;
}

pub struct BleMesh {
    config: BleConfig,
    peers: Arc<RwLock<HashMap<String, BlePeer>>>,
    connected_peers: Arc<RwLock<Vec<String>>>,
    message_sender: Option<mpsc::Sender<(String, Vec<u8>)>>,
    message_receiver: Arc<RwLock<Option<mpsc::Receiver<(String, Vec<u8>)>>>>,
    advertising: Arc<RwLock<bool>>,
    scanning: Arc<RwLock<bool>>,
    initialized: Arc<RwLock<bool>>,
}

impl BleMesh {
    #[instrument(skip_all, name = "BleMesh::new")]
    pub fn new(config: BleConfig) -> AnyhowResult<Self> {
        let (tx, rx) = mpsc::channel(100);

        info!(
            service = %config.service_uuid,
            characteristic = %config.characteristic_uuid,
            "BLE mesh initialized"
        );

        Ok(Self {
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            connected_peers: Arc::new(RwLock::new(Vec::new())),
            message_sender: Some(tx),
            message_receiver: Arc::new(RwLock::new(Some(rx))),
            advertising: Arc::new(RwLock::new(false)),
            scanning: Arc::new(RwLock::new(false)),
            initialized: Arc::new(RwLock::new(false)),
        })
    }

    pub async fn initialize(&self) -> MeshResult<()> {
        if *self.initialized.read() {
            return Ok(());
        }

        info!("Initializing BLE adapter");
        
        #[cfg(target_os = "linux")]
        {
            self.initialize_linux().await?;
        }

        *self.initialized.write() = true;
        
        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn initialize_linux(&self) -> MeshResult<()> {
        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn connect(&self) -> MeshResult<()> {
        self.initialize().await?;

        if *self.advertising.read() {
            debug!("Already advertising");
            return Ok(());
        }

        self.start_advertising().await?;
        self.start_discovery().await?;

        Ok(())
    }

    async fn start_advertising(&self) -> MeshResult<()> {
        *self.advertising.write() = true;
        
        info!(
            name = %self.config.device_name,
            "Started BLE advertising"
        );

        Ok(())
    }

    async fn start_discovery(&self) -> MeshResult<()> {
        *self.scanning.write() = true;

        info!("Started BLE discovery");

        Ok(())
    }

    pub async fn discover_peers(&self) -> Vec<BlePeer> {
        if !*self.initialized.read() {
            warn!("BLE not initialized");
            return Vec::new();
        }

        let peers = self.peers.read();
        peers.values().cloned().collect()
    }

    pub async fn connect_to_peer(&self, peer_id: &str) -> MeshResult<()> {
        let peer = {
            let peers = self.peers.read();
            peers.get(peer_id).cloned()
        };

        let peer = peer.ok_or_else(|| MeshError::BleError("Peer not found".to_string()))?;

        self.connect_to(&peer).await
    }

    async fn connect_to(&self, _peer: &BlePeer) -> MeshResult<()> {
        debug!(peer = %peer.id, "Connecting to BLE peer");

        let mut connected = self.connected_peers.write();
        if !connected.contains(&peer.id) {
            connected.push(peer.id.clone());
        }

        info!(peer = %peer.id, "Connected to BLE peer");

        Ok(())
    }

    pub async fn disconnect_peer(&self, peer_id: &str) -> MeshResult<()> {
        let mut connected = self.connected_peers.write();
        connected.retain(|id| id != peer_id);

        info!(peer = %peer_id, "Disconnected from BLE peer");

        Ok(())
    }

    pub async fn send(&self, data: &[u8], destination: &str) -> MeshResult<()> {
        let connected = self.connected_peers.read();
        
        if !connected.contains(&destination.to_string()) {
            return Err(MeshError::BleError("Peer not connected".to_string()));
        }

        if let Some(ref sender) = self.message_sender {
            sender.send((destination.to_string(), data.to_vec()))
                .await
                .map_err(|e| MeshError::SendFailed(e.to_string()))?;
        }

        debug!(peer = %destination, bytes = %data.len(), "Sent BLE message");

        Ok(())
    }

    pub async fn broadcast(&self, data: &[u8]) -> MeshResult<()> {
        let connected = self.connected_peers.read();

        for peer_id in connected.iter() {
            if let Some(ref sender) = self.message_sender {
                let _ = sender.send((peer_id.clone(), data.to_vec())).await;
            }
        }

        debug!(peers = %connected.len(), bytes = %data.len(), "Broadcast BLE message");

        Ok(())
    }

    pub async fn receive(&self) -> Option<(String, Vec<u8>)> {
        let mut receiver = self.message_receiver.write();
        if let Some(ref mut rx) = *receiver {
            rx.recv().await
        } else {
            None
        }
    }

    pub fn get_connected_peers(&self) -> Vec<String> {
        self.connected_peers.read().clone()
    }

    pub fn is_advertising(&self) -> bool {
        *self.advertising.read()
    }

    pub fn is_scanning(&self) -> bool {
        *self.scanning.read()
    }

    pub async fn shutdown(&self) -> MeshResult<()> {
        info!("Shutting down BLE mesh");

        *self.advertising.write() = false;
        *self.scanning.write() = false;

        let mut connected = self.connected_peers.write();
        connected.clear();

        Ok(())
    }
}

impl BleDiscovery for BleMesh {
    async fn discover(&mut self) -> Vec<BlePeer> {
        self.discover_peers().await
    }

    async fn connect(&mut self, peer: &BlePeer) -> MeshResult<()> {
        self.connect_to(peer).await
    }

    async fn disconnect(&mut self, peer: &BlePeer) -> MeshResult<()> {
        self.disconnect_peer(&peer.id).await
    }

    async fn send(&mut self, data: &[u8], peer_id: &str) -> MeshResult<()> {
        self.send(data, peer_id).await
    }

    async fn receive(&mut self) -> Option<(String, Vec<u8>)> {
        self.receive().await
    }
}

#[derive(Debug, Clone)]
pub struct BleMeshMessage {
    pub source_id: String,
    pub destination_id: String,
    pub payload: Vec<u8>,
    pub timestamp: u64,
    pub hop_count: u8,
    pub message_id: String,
}

impl BleMeshMessage {
    pub fn new(source_id: String, destination_id: String, payload: Vec<u8>) -> Self {
        let message_id = uuid::Uuid::new_v4().to_string();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            source_id,
            destination_id,
            payload,
            timestamp,
            hop_count: 0,
            message_id,
        }
    }
}

pub struct BleMeshProtocol {
    mesh: Arc<BleMesh>,
    local_id: String,
    routing_table: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl BleMeshProtocol {
    pub fn new(mesh: Arc<BleMesh>, local_id: String) -> Self {
        Self {
            mesh,
            local_id,
            routing_table: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn route_message(&self, message: BleMeshMessage) -> MeshResult<()> {
        let destination = &message.destination_id;

        let connected = self.mesh.get_connected_peers();
        
        if connected.contains(destination) {
            self.mesh.send(&message.payload, destination).await?;
            return Ok(());
        }

        let routing = self.routing_table.read();
        if let Some(hop) = routing.get(destination) {
            if let Some(first_hop) = hop.first() {
                self.mesh.send(&message.payload, first_hop).await?;
                return Ok(());
            }
        }

        Err(MeshError::BleError("No route to destination".to_string()))
    }

    pub fn update_routing(&self, destination: String, via: Vec<String>) {
        let mut routing = self.routing_table.write();
        routing.insert(destination, via);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ble_config_defaults() {
        let config = BleConfig::default();
        assert_eq!(config.device_name, "VigilNet-Agent");
        assert_eq!(config.max_connections, 5);
    }

    #[tokio::test]
    async fn test_ble_mesh_creation() -> AnyhowResult<()> {
        let config = BleConfig::default();
        let mesh = BleMesh::new(config)?;
        assert!(!mesh.is_advertising());
        assert!(!mesh.is_scanning());
        Ok(())
    }
}
