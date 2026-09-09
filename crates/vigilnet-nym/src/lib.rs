//! VigilNet Nym
//!
//! Nym mixnet integration for metadata-resistant communication.
//! Provides 5-hop mixnet routing with cover traffic and Sphinx packets.

pub mod client;
pub mod mixnet;

use async_trait::async_trait;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

pub use client::{NymClient, NymState};
pub use mixnet::{CoverTrafficConfig, Gateway, MixNode, MixnetTopology};

#[derive(Debug, thiserror::Error)]
pub enum NymError {
    #[error("Nym client not connected: {0}")]
    NotConnected(String),

    #[error("Mixnet routing failed: {0}")]
    RoutingFailed(String),

    #[error("Gateway error: {0}")]
    GatewayError(String),

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

pub type Result<T> = std::result::Result<T, NymError>;

pub struct NymTransport {
    client: Arc<RwLock<NymClient>>,
    local_addr: SocketAddr,
    e2ee_enabled: bool,
    encryptor: Option<vigilnet_crypto::e2ee::DoubleRatchet>,
    pending_messages: Arc<RwLock<Vec<(String, Vec<u8>)>>>,
}

impl NymTransport {
    pub fn new(client: NymClient) -> Self {
        Self {
            client: Arc::new(RwLock::new(client)),
            local_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            e2ee_enabled: false,
            encryptor: None,
            pending_messages: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn connect(&self) -> Result<()> {
        let mut client = self.client.write().await;
        client.connect().await?;
        
        if let Some(addr) = client.address() {
            info!("Nym transport connected with address: {}", addr);
        }
        
        Ok(())
    }

    pub fn enable_e2ee(&mut self, prekey_bundle: vigilnet_crypto::PreKeyBundle) -> Result<()> {
        let identity_key = vigilnet_crypto::IdentityKeyPair::generate();
        self.encryptor = Some(
            vigilnet_crypto::e2ee::DoubleRatchet::new_alice(
                identity_key,
                prekey_bundle,
            )
            .map_err(|e| NymError::E2eeError(e.to_string()))?
        );
        self.e2ee_enabled = true;
        info!("Nym E2EE enabled");
        Ok(())
    }

    pub async fn send_to(&self, recipient: &str, data: &[u8]) -> Result<()> {
        let payload = if self.e2ee_enabled {
            if let Some(ref mut enc) = self.encryptor {
                let encrypted = enc.encrypt_message(data)
                    .map_err(|e| NymError::E2eeError(e.to_string()))?;
                encrypted.into_bytes()
            } else {
                data.to_vec()
            }
        } else {
            data.to_vec()
        };

        let client = self.client.read().await;
        client.send(recipient, &payload).await
    }

    pub async fn receive(&self) -> Result<(String, Vec<u8>)> {
        let mut client = self.client.write().await;
        let (sender, data) = client.wait_for_message().await?;
        
        let decrypted = if self.e2ee_enabled {
            if let Some(ref mut enc) = self.encryptor {
                enc.decrypt_message(&data)
                    .map_err(|e| NymError::E2eeError(e.to_string()))?
            } else {
                data
            }
        } else {
            data
        };
        
        Ok((sender, decrypted))
    }

    pub fn address(&self) -> Option<String> {
        self.client.blocking_read().address().map(String::from)
    }
}

#[async_trait]
impl vigilnet_agent_transport::AgentTransport for NymTransport {
    async fn bind(&mut self) -> vigilnet_agent_transport::TransportResult<()> {
        self.connect().await
            .map_err(|e| vigilnet_agent_transport::TransportError::Bind(e.to_string()))?;
        
        if let Some(addr) = self.address() {
            info!("Nym transport bound: {}", addr);
        }
        
        Ok(())
    }

    async fn connect(&self, addr: SocketAddr) -> vigilnet_agent_transport::TransportResult<Box<dyn vigilnet_agent_transport::AgentConnection>> {
        let host = addr.ip().to_string();
        let port = addr.port();
        let recipient = format!("{}:{}", host, port);
        
        info!("Connecting to Nym recipient: {}", recipient);
        
        Ok(Box::new(NymAgentConnection {
            transport: self.client.clone(),
            recipient,
            pending: self.pending_messages.clone(),
            e2ee_enabled: self.e2ee_enabled,
            encryptor: self.encryptor.clone(),
        }))
    }

    async fn accept(&self) -> vigilnet_agent_transport::TransportResult<Box<dyn vigilnet_agent_transport::AgentConnection>> {
        warn!("Nym doesn't support traditional accept, use receive");
        Err(vigilnet_agent_transport::TransportError::NotAvailable(
            "Use receive() to get incoming messages".into()
        ))
    }

    async fn shutdown(&mut self) -> vigilnet_agent_transport::TransportResult<()> {
        let mut client = self.client.write().await;
        client.disconnect().await;
        info!("Nym transport shutdown");
        Ok(())
    }

    fn transport_kind(&self) -> vigilnet_agent_transport::TransportKind {
        vigilnet_agent_transport::TransportKind::Nym
    }

    fn local_addr(&self) -> vigilnet_agent_transport::TransportResult<SocketAddr> {
        Ok(self.local_addr)
    }
}

pub struct NymAgentConnection {
    transport: Arc<RwLock<NymClient>>,
    recipient: String,
    pending: Arc<RwLock<Vec<(String, Vec<u8>)>>>,
    e2ee_enabled: bool,
    encryptor: Option<vigilnet_crypto::e2ee::DoubleRatchet>,
}

#[async_trait]
impl vigilnet_agent_transport::AgentConnection for NymAgentConnection {
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

        let client = self.transport.read().await;
        client.send(&self.recipient, &payload).await
            .map_err(|e| vigilnet_agent_transport::TransportError::Send(e.to_string()))
    }

    async fn recv(&self) -> vigilnet_agent_transport::TransportResult<Bytes> {
        let mut client = self.transport.write().await;
        
        let (sender, data) = client.wait_for_message().await
            .map_err(|e| vigilnet_agent_transport::TransportError::Recv(e.to_string()))?;
        
        let decrypted = if self.e2ee_enabled {
            if let Some(ref mut enc) = self.encryptor.as_ref() {
                enc.decrypt_message(&data)
                    .map_err(|e| vigilnet_agent_transport::TransportError::Recv(e.to_string()))?
            } else {
                data
            }
        } else {
            data
        };
        
        Ok(Bytes::from(decrypted))
    }

    fn remote_addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 0))
    }

    fn transport_kind(&self) -> vigilnet_agent_transport::TransportKind {
        vigilnet_agent_transport::TransportKind::Nym
    }

    async fn close(&self) -> vigilnet_agent_transport::TransportResult<()> {
        Ok(())
    }
}
