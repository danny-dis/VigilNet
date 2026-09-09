//! VigilNet Tor
//!
//! Tor network integration via the Arti library.
//! Provides onion routing through the Tor network as an alternative
//! transport backend for VigilNet agents.

pub mod client;
pub mod bridge;
pub mod onion_service;

use async_trait::async_trait;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

pub use client::{IsolationPolicy, TorClient, TorState};
pub use bridge::{BridgeConfig, BridgeManager, TransportType};
pub use onion_service::{OnionService, OnionServiceManager};

/// Tor-specific error types
#[derive(Debug, thiserror::Error)]
pub enum TorError {
    #[error("Tor client not initialized")]
    NotInitialized,

    #[error("Tor bootstrap failed: {0}")]
    BootstrapFailed(String),

    #[error("Tor circuit creation failed: {0}")]
    CircuitFailed(String),

    #[error("Bridge configuration error: {0}")]
    BridgeError(String),

    #[error("Onion service error: {0}")]
    OnionServiceError(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Send error: {0}")]
    SendError(String),

    #[error("Recv error: {0}")]
    RecvError(String),

    #[error("E2EE error: {0}")]
    E2eeError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for Tor operations
pub type Result<T> = std::result::Result<T, TorError>;

/// Tor transport for agent network
pub struct TorTransport {
    client: Arc<RwLock<TorClient>>,
    onion_service: Arc<RwLock<OnionServiceManager>>,
    local_addr: SocketAddr,
    e2ee_enabled: bool,
    encryptor: Option<vigilnet_crypto::e2ee::DoubleRatchet>,
}

impl TorTransport {
    pub fn new(client: TorClient) -> Self {
        Self {
            client: Arc::new(RwLock::new(client)),
            onion_service: Arc::new(RwLock::new(OnionServiceManager::new())),
            local_addr: SocketAddr::from(([127, 0, 0, 1], 9150)),
            e2ee_enabled: false,
            encryptor: None,
        }
    }

    pub fn with_onion_service(mut self, manager: OnionServiceManager) -> Self {
        self.onion_service = Arc::new(RwLock::new(manager));
        self
    }

    pub fn enable_e2ee(&mut self, prekey_bundle: vigilnet_crypto::PreKeyBundle) -> Result<()> {
        let identity_key = vigilnet_crypto::IdentityKeyPair::generate();
        self.encryptor = Some(
            vigilnet_crypto::e2ee::DoubleRatchet::new_alice(
                identity_key,
                prekey_bundle,
            )
            .map_err(|e| TorError::E2eeError(e.to_string()))?
        );
        self.e2ee_enabled = true;
        info!("Tor E2EE enabled");
        Ok(())
    }

    pub async fn create_onion_service(
        &self,
        local_port: u16,
        virtual_port: u16,
    ) -> Result<OnionService> {
        let mut manager = self.onion_service.write().await;
        manager.create_service(local_port, virtual_port).await
    }

    pub async fn connect_tor(&self, host: &str, port: u16) -> Result<TorStreamConnection> {
        let client = self.client.read().await;
        
        if client.state() != TorState::Connected {
            return Err(TorError::NotInitialized);
        }

        let stream = client.connect(host, port).await?;
        
        Ok(TorStreamConnection {
            stream,
            e2ee_enabled: self.e2ee_enabled,
            encryptor: self.encryptor.as_ref().map(|e| e.clone()),
        })
    }
}

#[derive(Clone)]
pub struct TorStreamConnection {
    stream: arti_client::DataStream,
    e2ee_enabled: bool,
    encryptor: Option<vigilnet_crypto::e2ee::DoubleRatchet>,
}

impl TorStreamConnection {
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        let payload = if self.e2ee_enabled {
            if let Some(ref mut enc) = self.encryptor {
                let encrypted = enc.encrypt_message(data)
                    .map_err(|e| TorError::E2eeError(e.to_string()))?;
                encrypted.into_bytes()
            } else {
                data.to_vec()
            }
        } else {
            data.to_vec()
        };

        use tokio::io::AsyncWriteExt;
        self.stream.write_all(&payload).await
            .map_err(|e| TorError::SendError(e.to_string()))
    }

    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        use tokio::io::AsyncReadExt;
        let n = self.stream.read(buf).await
            .map_err(|e| TorError::RecvError(e.to_string()))?;
        
        if self.e2ee_enabled && n > 0 {
            if let Some(ref mut enc) = self.encryptor {
                let decrypted = enc.decrypt_message(&buf[..n])
                    .map_err(|e| TorError::E2eeError(e.to_string()))?;
                buf[..decrypted.len()].copy_from_slice(&decrypted);
                return Ok(decrypted.len());
            }
        }
        
        Ok(n)
    }
}

#[async_trait]
impl vigilnet_agent_transport::AgentTransport for TorTransport {
    async fn bind(&mut self) -> vigilnet_agent_transport::TransportResult<()> {
        let mut client = self.client.write().await;
        client.start().await
            .map_err(|e| vigilnet_agent_transport::TransportError::Bind(e.to_string()))?;
        
        info!("Tor transport bound");
        Ok(())
    }

    async fn connect(&self, addr: SocketAddr) -> vigilnet_agent_transport::TransportResult<Box<dyn vigilnet_agent_transport::AgentConnection>> {
        let host = addr.ip().to_string();
        let port = addr.port();
        
        let conn = self.connect_tor(&host, port).await
            .map_err(|e| vigilnet_agent_transport::TransportError::ConnectionFailed(e.to_string()))?;
        
        Ok(Box::new(TorAgentConnection {
            connection: conn,
            remote_addr: addr,
        }))
    }

    async fn accept(&self) -> vigilnet_agent_transport::TransportResult<Box<dyn vigilnet_agent_transport::AgentConnection>> {
        warn!("Tor doesn't support inbound connections directly, use onion services");
        Err(vigilnet_agent_transport::TransportError::NotAvailable("Use onion services".into()))
    }

    async fn shutdown(&mut self) -> vigilnet_agent_transport::TransportResult<()> {
        let mut client = self.client.write().await;
        client.stop().await;
        info!("Tor transport shutdown");
        Ok(())
    }

    fn transport_kind(&self) -> vigilnet_agent_transport::TransportKind {
        vigilnet_agent_transport::TransportKind::Tor
    }

    fn local_addr(&self) -> vigilnet_agent_transport::TransportResult<SocketAddr> {
        Ok(self.local_addr)
    }
}

pub struct TorAgentConnection {
    connection: TorStreamConnection,
    remote_addr: SocketAddr,
}

#[async_trait]
impl vigilnet_agent_transport::AgentConnection for TorAgentConnection {
    async fn send(&self, data: Bytes) -> vigilnet_agent_transport::TransportResult<()> {
        self.connection.send(&data).await
            .map_err(|e| vigilnet_agent_transport::TransportError::Send(e.to_string()))
    }

    async fn recv(&self) -> vigilnet_agent_transport::TransportResult<Bytes> {
        let mut buf = vec![0u8; 65536];
        let n = self.connection.recv(&mut buf).await
            .map_err(|e| vigilnet_agent_transport::TransportError::Recv(e.to_string()))?;
        Ok(Bytes::from(buf[..n].to_vec()))
    }

    fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    fn transport_kind(&self) -> vigilnet_agent_transport::TransportKind {
        vigilnet_agent_transport::TransportKind::Tor
    }

    async fn close(&self) -> vigilnet_agent_transport::TransportResult<()> {
        Ok(())
    }
}
