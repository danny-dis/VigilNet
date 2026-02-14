//! QUIC transport for NAT traversal with optional app-layer E2EE

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};

use crate::secure_transport::SecureTransport;
use crate::{TransportConfig, TransportError, TransportResult, Transport};

const DEFAULT_QUIC_PORT: u16 = 9001;
const MAX_DATAGRAM_SIZE: usize = 1350;

pub struct QuicTransport {
    config: TransportConfig,
    listen_addr: String,
    secure_mode: bool,
    secure_transport: Option<SecureTransport<QuicTransport>>,
    running: Arc<RwLock<bool>>,
    connections: Arc<RwLock<HashMap<String, QuicConnection>>>,
    shutdown_tx: Option<broadcast::Sender<()>>,
    message_tx: Option<broadcast::Sender<(String, Vec<u8>)>>,
}

struct QuicConnection {
    address: String,
    connected: bool,
    remote_peer_id: Option<String>,
}

impl QuicTransport {
    pub fn new() -> Self {
        Self {
            config: TransportConfig::default(),
            listen_addr: format!("/ip4/0.0.0.0/udp/{}", DEFAULT_QUIC_PORT),
            secure_mode: false,
            secure_transport: None,
            running: Arc::new(RwLock::new(false)),
            connections: Arc::new(RwLock::new(HashMap::new())),
            shutdown_tx: None,
            message_tx: None,
        }
    }

    pub fn with_config(mut self, config: TransportConfig) -> Self {
        self.config = config;
        self
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        if !enabled {
            self.config.max_connections = 0;
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.max_connections > 0
    }

    pub fn with_listen_addr(mut self, addr: String) -> Self {
        self.listen_addr = addr;
        self
    }

    pub fn enable_e2ee(mut self) -> Self {
        self.secure_mode = true;
        self
    }

    pub fn is_e2ee_enabled(&self) -> bool {
        self.secure_mode
    }

    pub fn with_secure_transport(mut self, secure: SecureTransport<QuicTransport>) -> Self {
        self.secure_transport = Some(secure);
        self
    }

    pub fn secure(&self) -> Option<&SecureTransport<QuicTransport>> {
        self.secure_transport.as_ref()
    }

    pub fn secure_mut(&mut self) -> Option<&mut SecureTransport<QuicTransport>> {
        self.secure_transport.as_mut()
    }

    pub async fn connect(&self, addr: &str) -> TransportResult<String> {
        let address = Self::parse_addr(addr)?;
        
        info!("QUIC connect to {} (simulated)", address);
        
        let conn_id = format!("quic-{}", uuid::Uuid::new_v4());
        
        let conn = QuicConnection {
            address: address.to_string(),
            connected: true,
            remote_peer_id: None,
        };
        
        self.connections.write().await.insert(conn_id.clone(), conn);
        
        Ok(conn_id)
    }

    pub async fn connect_with_e2ee(
        &self,
        addr: &str,
        peer_identity: [u8; 32],
    ) -> TransportResult<String> {
        let secure = self.secure_transport.as_ref().ok_or_else(|| {
            TransportError::ConnectionFailed("E2EE not configured".into())
        })?;

        let bundle = secure
            .session_manager()
            .get_prekey_bundle()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        secure
            .establish_session(peer_identity, &bundle)
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))
    }

    pub async fn send_datagram(&self, peer_id: &str, data: &[u8]) -> TransportResult<usize> {
        let mut connections = self.connections.write().await;
        let conn = connections
            .get_mut(peer_id)
            .ok_or_else(|| TransportError::PeerNotFound(peer_id.to_string()))?;

        if !conn.connected {
            return Err(TransportError::ConnectionFailed(
                "Connection closed".into(),
            ));
        }

        if data.len() > MAX_DATAGRAM_SIZE {
            return Err(TransportError::Buffer(format!(
                "Datagram too large: {} > {}",
                data.len(),
                MAX_DATAGRAM_SIZE
            )));
        }

        debug!("QUIC sent {} bytes to {}", data.len(), peer_id);
        Ok(data.len())
    }

    pub async fn send_stream(&self, peer_id: &str, data: &[u8]) -> TransportResult<usize> {
        self.send_datagram(peer_id, data).await
    }

    pub async fn send_app_layer_encrypted(
        &self,
        peer_identity: [u8; 32],
        data: &[u8],
    ) -> TransportResult<Vec<u8>> {
        let secure = self.secure_transport.as_ref().ok_or_else(|| {
            TransportError::ConnectionFailed("E2EE not configured".into())
        })?;

        let encrypted = secure
            .encrypt_for_peer(peer_identity, data)
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        Ok(serde_json::to_vec(&encrypted)
            .map_err(TransportError::Serialization)?)
    }

    pub async fn receive_datagram(&self, timeout_ms: u64) -> TransportResult<(String, Vec<u8>)> {
        tokio::time::sleep(Duration::from_millis(timeout_ms)).await;
        Err(TransportError::Timeout("No datagram available".into()))
    }

    pub async fn receive_app_layer_encrypted(
        &self,
        data: &[u8],
    ) -> TransportResult<(String, Vec<u8>)> {
        let secure = self.secure_transport.as_ref().ok_or_else(|| {
            TransportError::ConnectionFailed("E2EE not configured".into())
        })?;

        let message = serde_json::from_slice(data)
            .map_err(TransportError::Serialization)?;

        let plaintext = secure
            .decrypt(&message)
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        Ok((message.session_id, plaintext))
    }

    pub async fn disconnect(&self, peer_id: &str) -> TransportResult<()> {
        let mut connections = self.connections.write().await;
        if let Some(conn) = connections.get_mut(peer_id) {
            conn.connected = false;
            info!("Disconnected QUIC peer {}", peer_id);
        }
        connections.remove(peer_id);
        Ok(())
    }

    pub async fn connected_peers(&self) -> Vec<String> {
        let connections = self.connections.read().await;
        connections
            .iter()
            .filter(|(_, c)| c.connected)
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub fn config(&self) -> &TransportConfig {
        &self.config
    }

    fn parse_addr(addr: &str) -> TransportResult<SocketAddr> {
        let addr = addr
            .strip_prefix("/ip4/")
            .or_else(|| addr.strip_prefix("udp://"))
            .unwrap_or(addr);
        
        addr.parse()
            .map_err(|e| TransportError::ConnectionFailed(format!("Invalid address: {}", e)))
    }
}

impl Default for QuicTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Transport for QuicTransport {
    fn start(&self) -> TransportResult<()> {
        if *self.running.blocking_read() {
            return Ok(());
        }

        let socket_addr = Self::parse_addr(&self.listen_addr)?;
        
        info!("Starting QUIC transport on {}", socket_addr);

        *self.running.write().await = true;

        let (shutdown_tx, _) = broadcast::channel(1);
        let (message_tx, _) = broadcast::channel(100);
        
        self.shutdown_tx = Some(shutdown_tx);
        self.message_tx = Some(message_tx);

        Ok(())
    }

    fn stop(&self) -> TransportResult<()> {
        info!("Stopping QUIC transport");
        
        *self.running.write().await = false;
        
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(());
        }

        self.connections.write().await.clear();

        Ok(())
    }

    fn is_running(&self) -> bool {
        *self.running.blocking_read()
    }

    fn local_peer_id(&self) -> Option<String> {
        Some(format!("quic-local-{}", uuid::Uuid::new_v4()))
    }
}

#[derive(Clone)]
pub struct QuicConfig {
    pub max_idle_timeout_ms: u64,
    pub max_concurrent_bidi_streams: u64,
    pub max_concurrent_uni_streams: u64,
    pub max_datagram_size: usize,
    pub enable_0rtt: bool,
    pub enable_early_data: bool,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            max_idle_timeout_ms: 60_000,
            max_concurrent_bidi_streams: 100,
            max_concurrent_uni_streams: 100,
            max_datagram_size: MAX_DATAGRAM_SIZE,
            enable_0rtt: true,
            enable_early_data: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_quic_transport_creation() {
        let transport = QuicTransport::new();
        assert!(transport.is_enabled());
        assert!(!transport.is_e2ee_enabled());
    }

    #[tokio::test]
    async fn test_quic_config_defaults() {
        let config = QuicConfig::default();
        assert_eq!(config.max_datagram_size, MAX_DATAGRAM_SIZE);
        assert!(config.enable_0rtt);
    }
}
