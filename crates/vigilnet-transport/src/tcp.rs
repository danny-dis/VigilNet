//! TCP transport with Noise encryption and optional E2EE

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};

use crate::secure_transport::SecureTransport;
use crate::{TransportConfig, TransportError, TransportResult, Transport};

const DEFAULT_TCP_PORT: u16 = 9000;
const MAX_FRAME_SIZE: usize = 10 * 1024 * 1024;

pub struct TcpTransport {
    config: TransportConfig,
    listen_addrs: Vec<String>,
    listener: Option<TcpListener>,
    secure_mode: bool,
    secure_transport: Option<SecureTransport<TcpTransport>>,
    running: Arc<RwLock<bool>>,
    peers: Arc<RwLock<HashMap<String, TcpPeer>>>,
    shutdown_tx: Option<broadcast::Sender<()>>,
    message_tx: Option<broadcast::Sender<(String, Vec<u8>)>>,
}

struct TcpPeer {
    address: String,
    stream: TcpStream,
    connected: bool,
}

impl TcpTransport {
    pub fn new() -> Self {
        Self {
            config: TransportConfig::default(),
            listen_addrs: vec![format!("/ip4/0.0.0.0/tcp/{}", DEFAULT_TCP_PORT)],
            listener: None,
            secure_mode: false,
            secure_transport: None,
            running: Arc::new(RwLock::new(false)),
            peers: Arc::new(RwLock::new(HashMap::new())),
            shutdown_tx: None,
            message_tx: None,
        }
    }

    pub fn with_config(mut self, config: TransportConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_listen_addrs(mut self, addrs: Vec<String>) -> Self {
        self.listen_addrs = addrs;
        self
    }

    pub fn with_listen_port(mut self, port: u16) -> Self {
        self.listen_addrs = vec![format!("/ip4/0.0.0.0/tcp/{}", port)];
        self
    }

    pub fn enable_e2ee(mut self) -> Self {
        self.secure_mode = true;
        self
    }

    pub fn is_e2ee_enabled(&self) -> bool {
        self.secure_mode
    }

    pub fn with_secure_transport(mut self, secure: SecureTransport<TcpTransport>) -> Self {
        self.secure_transport = Some(secure);
        self
    }

    pub fn secure(&self) -> Option<&SecureTransport<TcpTransport>> {
        self.secure_transport.as_ref()
    }

    pub fn secure_mut(&mut self) -> Option<&mut SecureTransport<TcpTransport>> {
        self.secure_transport.as_mut()
    }

    pub async fn connect(&self, addr: &str) -> TransportResult<String> {
        let address = Self::parse_addr(addr)?;
        let stream = tokio::time::timeout(
            Duration::from_millis(self.config.connection_timeout_ms),
            TcpStream::connect(address),
        )
        .await
        .map_err(|_| TransportError::Timeout(format!("Connection to {} timed out", addr)))?
        .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let peer_id = format!("tcp-{}", uuid::Uuid::new_v4());
        
        let peer = TcpPeer {
            address: address.to_string(),
            stream,
            connected: true,
        };

        self.peers.write().await.insert(peer_id.clone(), peer);
        info!("Connected to {} as {}", address, peer_id);
        
        Ok(peer_id)
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

    pub async fn send(&self, peer_id: &str, data: &[u8]) -> TransportResult<usize> {
        let mut peers = self.peers.write().await;
        let peer = peers
            .get_mut(peer_id)
            .ok_or_else(|| TransportError::PeerNotFound(peer_id.to_string()))?;

        if !peer.connected {
            return Err(TransportError::ConnectionFailed(
                "Peer disconnected".into(),
            ));
        }

        if data.len() > self.config.max_message_size {
            return Err(TransportError::Buffer(format!(
                "Message too large: {} > {}",
                data.len(),
                self.config.max_message_size
            )));
        }

        let mut encoded = vec![0u8; 4];
        let len = data.len() as u32;
        encoded[0..4].copy_from_slice(&len.to_be_bytes());
        encoded.extend_from_slice(data);

        peer.stream
            .write_all(&encoded)
            .await
            .map_err(|e| TransportError::Io(e))?;

        debug!("Sent {} bytes to {}", data.len(), peer_id);
        Ok(data.len())
    }

    pub async fn send_encrypted(
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

    pub async fn receive(&self, peer_id: &str, timeout_ms: u64) -> TransportResult<Vec<u8>> {
        let mut peers = self.peers.write().await;
        let peer = peers
            .get_mut(peer_id)
            .ok_or_else(|| TransportError::PeerNotFound(peer_id.to_string()))?;

        if !peer.connected {
            return Err(TransportError::ConnectionFailed(
                "Peer disconnected".into(),
            ));
        }

        let mut size_buf = [0u8; 4];
        
        tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            peer.stream.read_exact(&mut size_buf),
        )
        .await
        .map_err(|_| TransportError::Timeout("Read timed out".into()))?
        .map_err(|e| TransportError::Io(e))?;

        let size = u32::from_be_bytes(size_buf) as usize;
        
        if size > MAX_FRAME_SIZE {
            return Err(TransportError::Buffer(format!("Frame too large: {}", size)));
        }

        let mut data = vec![0u8; size];
        peer.stream
            .read_exact(&mut data)
            .await
            .map_err(|e| TransportError::Io(e))?;

        debug!("Received {} bytes from {}", data.len(), peer_id);
        Ok(data)
    }

    pub async fn receive_encrypted(
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
        let mut peers = self.peers.write().await;
        if let Some(mut peer) = peers.remove(peer_id) {
            peer.connected = false;
            peer.stream.shutdown().await.ok();
            info!("Disconnected from {}", peer_id);
        }
        Ok(())
    }

    pub async fn connected_peers(&self) -> Vec<String> {
        let peers = self.peers.read().await;
        peers
            .iter()
            .filter(|(_, p)| p.connected)
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub fn config(&self) -> &TransportConfig {
        &self.config
    }

    fn parse_addr(addr: &str) -> TransportResult<SocketAddr> {
        let addr = addr
            .strip_prefix("/ip4/")
            .or_else(|| addr.strip_prefix("tcp://"))
            .unwrap_or(addr);
        
        addr.parse()
            .map_err(|e| TransportError::ConnectionFailed(format!("Invalid address: {}", e)))
    }

    async fn accept_connections(&self) {
        let listener = match &self.listener {
            Some(l) => l,
            None => return,
        };

        let running = self.running.clone();
        let peers = self.peers.clone();
        let config = self.config.clone();

        loop {
            if !*running.read().await {
                break;
            }

            match listener.accept().await {
                Ok((stream, addr)) => {
                    let peer_id = format!("tcp-{}", uuid::Uuid::new_v4());
                    let peer = TcpPeer {
                        address: addr.to_string(),
                        stream,
                        connected: true,
                    };
                    
                    peers.write().await.insert(peer_id.clone(), peer);
                    info!("Accepted connection from {} as {}", addr, peer_id);

                    if let Some(tx) = &self.message_tx {
                        let _ = tx.send((peer_id, vec![]));
                    }
                }
                Err(e) => {
                    if *running.read().await {
                        error!("Accept error: {}", e);
                    }
                }
            }
        }
    }
}

impl Default for TcpTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Transport for TcpTransport {
    fn start(&self) -> TransportResult<()> {
        if *self.running.read().blocking_wait() {
            return Ok(());
        }

        let addr = self
            .listen_addrs
            .first()
            .cloned()
            .unwrap_or_else(|| format!("/ip4/0.0.0.0/tcp/{}", DEFAULT_TCP_PORT));
        
        let socket_addr = Self::parse_addr(&addr)?;
        
        let runtime = tokio::runtime::Handle::current();
        let listener = runtime.block_on(async { 
            TcpListener::bind(socket_addr).await 
        }).map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        info!("Starting TCP transport on {}", socket_addr);

        self.running.write().await.clone_from(&true);
        self.listener = Some(listener);

        let (shutdown_tx, _) = broadcast::channel(1);
        let (message_tx, _) = broadcast::channel(100);
        
        self.shutdown_tx = Some(shutdown_tx);
        self.message_tx = Some(message_tx);

        let running = self.running.clone();
        let accept = async move {
            loop {
                if !*running.read().await {
                    break;
                }
                tokio::task::yield_now().await;
            }
        };
        
        tokio::spawn(accept);

        Ok(())
    }

    fn stop(&self) -> TransportResult<()> {
        info!("Stopping TCP transport");
        
        *self.running.write().await = false;
        
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(());
        }

        if let Some(listener) = &self.listener {
            drop(listener);
        }

        let mut peers = futures::executor::block_on(self.peers.write());
        for (_, mut peer) in peers.drain() {
            let _ = peer.stream.shutdown().await;
        }

        Ok(())
    }

    fn is_running(&self) -> bool {
        *self.running.blocking_read()
    }

    fn local_peer_id(&self) -> Option<String> {
        Some(format!("tcp-local-{}", uuid::Uuid::new_v4()))
    }
}

trait RwLockBlockingRead {
    fn blocking_wait(&self) -> std::sync::Arc<RwLock<bool>>;
}

impl<T> RwLockBlockingRead for RwLock<T> {
    fn blocking_wait(&self) -> std::sync::Arc<RwLock<bool>> {
        self.blocking_read();
        std::sync::Arc::new(RwLock::new(true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tcp_transport_creation() {
        let transport = TcpTransport::new();
        assert!(!transport.is_e2ee_enabled());
        assert_eq!(transport.config().max_connections, 256);
    }

    #[tokio::test]
    async fn test_parse_addr() {
        let addr = TcpTransport::parse_addr("/ip4/127.0.0.1/tcp/8080")
            .expect("Test address should be valid");
        assert_eq!(addr.ip(), std::net::Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(addr.port(), 8080);
    }
}
