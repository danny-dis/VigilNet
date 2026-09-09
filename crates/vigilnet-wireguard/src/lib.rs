//! VigilNet WireGuard
//!
//! WireGuard tunnel integration via boringtun (userspace implementation).
//! Provides fast encrypted tunnels between nodes or as VPN exit.

pub mod tunnel;
pub mod config;

use async_trait::async_trait;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

pub use tunnel::{TunnelState, TunnelStats, WgTunnel};
pub use config::{PeerConfig, WireGuardConfig};

#[derive(Debug, thiserror::Error)]
pub enum WgError {
    #[error("Tunnel creation failed: {0}")]
    TunnelFailed(String),

    #[error("Peer configuration error: {0}")]
    PeerError(String),

    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Send error: {0}")]
    SendError(String),

    #[error("Recv error: {0}")]
    RecvError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, WgError>;

pub struct WireGuardTransport {
    tunnel: Arc<RwLock<WgTunnel>>,
    config: WireGuardConfig,
    local_addr: SocketAddr,
    e2ee_enabled: bool,
    encryptor: Option<vigilnet_crypto::e2ee::DoubleRatchet>,
}

impl WireGuardTransport {
    pub fn new(config: WireGuardConfig) -> Self {
        let private_key_bytes = base64::decode(&config.private_key)
            .unwrap_or_else(|_| {
                let mut key = [0u8; 32];
                rand::rngs::OsRng.fill(&mut key);
                key.to_vec()
            });
        
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes[..32.min(private_key_bytes.len())]);

        let mut tunnel = WgTunnel::new()
            .with_private_key(private_key)
            .with_keepalive(config.peers.first().and_then(|p| p.persistent_keepalive).unwrap_or(25));

        if let Some(peer) = config.peers.first() {
            if let Ok(peer_key) = base64::decode(&peer.public_key) {
                let mut key = [0u8; 32];
                key.copy_from_slice(&peer_key[..32.min(peer_key.len())]);
                tunnel = tunnel.with_peer_key(key);
            }

            if let Some(ref endpoint) = peer.endpoint {
                tunnel = tunnel.with_endpoint(endpoint);
            }

            tunnel = tunnel.with_allowed_ips(peer.allowed_ips.clone());
        }

        Self {
            tunnel: Arc::new(RwLock::new(tunnel)),
            config,
            local_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            e2ee_enabled: false,
            encryptor: None,
        }
    }

    pub async fn start(&self) -> Result<()> {
        let mut tunnel = self.tunnel.write().await;
        tunnel.start().await
    }

    pub fn enable_e2ee(&mut self, prekey_bundle: vigilnet_crypto::PreKeyBundle) -> Result<()> {
        let identity_key = vigilnet_crypto::IdentityKeyPair::generate();
        self.encryptor = Some(
            vigilnet_crypto::e2ee::DoubleRatchet::new_alice(
                identity_key,
                prekey_bundle,
            )
            .map_err(|e| WgError::CryptoError(e.to_string()))?
        );
        self.e2ee_enabled = true;
        info!("WireGuard E2EE enabled");
        Ok(())
    }

    pub async fn tunnel_state(&self) -> TunnelState {
        self.tunnel.read().await.state()
    }

    pub async fn stats(&self) -> TunnelStats {
        self.tunnel.read().await.stats().clone()
    }
}

#[async_trait]
impl vigilnet_agent_transport::AgentTransport for WireGuardTransport {
    async fn bind(&mut self) -> vigilnet_agent_transport::TransportResult<()> {
        self.start().await
            .map_err(|e| vigilnet_agent_transport::TransportError::Bind(e.to_string()))?;
        
        info!("WireGuard transport bound");
        Ok(())
    }

    async fn connect(&self, addr: SocketAddr) -> vigilnet_agent_transport::TransportResult<Box<dyn vigilnet_agent_transport::AgentConnection>> {
        let endpoint = format!("{}:{}", addr.ip(), addr.port());
        
        let mut tunnel = self.tunnel.write().await;
        tunnel.with_endpoint(&endpoint);
        tunnel.start().await
            .map_err(|e| vigilnet_agent_transport::TransportError::ConnectionFailed(e.to_string()))?;
        
        info!("WireGuard tunnel established to {}", endpoint);
        
        Ok(Box::new(WireGuardAgentConnection {
            tunnel: self.tunnel.clone(),
            remote_addr: addr,
            e2ee_enabled: self.e2ee_enabled,
            encryptor: self.encryptor.clone(),
        }))
    }

    async fn accept(&self) -> vigilnet_agent_transport::TransportResult<Box<dyn vigilnet_agent_transport::AgentConnection>> {
        warn!("WireGuard doesn't support accept - it's a tunnel, not a server");
        Err(vigilnet_agent_transport::TransportError::NotAvailable(
            "WireGuard is a point-to-point tunnel".into()
        ))
    }

    async fn shutdown(&mut self) -> vigilnet_agent_transport::TransportResult<()> {
        let mut tunnel = self.tunnel.write().await;
        tunnel.stop().await;
        info!("WireGuard transport shutdown");
        Ok(())
    }

    fn transport_kind(&self) -> vigilnet_agent_transport::TransportKind {
        vigilnet_agent_transport::TransportKind::WireGuard
    }

    fn local_addr(&self) -> vigilnet_agent_transport::TransportResult<SocketAddr> {
        Ok(self.local_addr)
    }
}

pub struct WireGuardAgentConnection {
    tunnel: Arc<RwLock<WgTunnel>>,
    remote_addr: SocketAddr,
    e2ee_enabled: bool,
    encryptor: Option<vigilnet_crypto::e2ee::DoubleRatchet>,
}

#[async_trait]
impl vigilnet_agent_transport::AgentConnection for WireGuardAgentConnection {
    async fn send(&self, data: Bytes) -> vigilnet_agent_transport::TransportResult<()> {
        let payload = if self.e2ee_enabled {
            if let Some(ref mut enc) = self.encryptor.as_ref() {
                let encrypted = enc.encrypt_message(&data)
                    .map_err(|e| vigilnet_agent_transport::TransportError::Send(e.to_string()))?;
                encrypted.into_bytes()
            } else {
                data.to_vec()
            }
        } else {
            data.to_vec()
        };

        let mut tunnel = self.tunnel.write().await;
        tunnel.encapsulate(&payload)
            .map_err(|e| vigilnet_agent_transport::TransportError::Send(e.to_string()))
    }

    async fn recv(&self) -> vigilnet_agent_transport::TransportResult<Bytes> {
        let mut tunnel = self.tunnel.write().await;
        let mut buf = vec![0u8; 65536];
        
        let decrypted = tunnel.decapsulate(&buf)
            .map_err(|e| vigilnet_agent_transport::TransportError::Recv(e.to_string()))?;
        
        if self.e2ee_enabled {
            if let Some(ref mut enc) = self.encryptor.as_ref() {
                let decrypted = enc.decrypt_message(&decrypted)
                    .map_err(|e| vigilnet_agent_transport::TransportError::Recv(e.to_string()))?;
                return Ok(Bytes::from(decrypted));
            }
        }
        
        Ok(Bytes::from(decrypted))
    }

    fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    fn transport_kind(&self) -> vigilnet_agent_transport::TransportKind {
        vigilnet_agent_transport::TransportKind::WireGuard
    }

    async fn close(&self) -> vigilnet_agent_transport::TransportResult<()> {
        Ok(())
    }
}
