//! VigilNet Freenet
//!
//! Freenet / Hyphanet integration for decentralized content storage
//! and retrieval through the Freenet network.

pub mod node;
pub mod content;
pub mod contracts;

use async_trait::async_trait;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

pub use node::{FreenetMode, FreenetNode, NodeState};
pub use content::{ContentKey, ContentMeta, ContentStore};
pub use contracts::{Contract, ContractExecutor};

#[derive(Debug, thiserror::Error)]
pub enum FreenetError {
    #[error("Freenet node not running: {0}")]
    NodeNotRunning(String),

    #[error("Content not found: {0}")]
    ContentNotFound(String),

    #[error("Content insert failed: {0}")]
    InsertFailed(String),

    #[error("Contract error: {0}")]
    ContractError(String),

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

pub type Result<T> = std::result::Result<T, FreenetError>;

pub struct FreenetTransport {
    node: Arc<RwLock<FreenetNode>>,
    content_store: Arc<ContentStore>,
    local_addr: SocketAddr,
    e2ee_enabled: bool,
    encryptor: Option<vigilnet_crypto::e2ee::DoubleRatchet>,
}

impl FreenetTransport {
    pub fn new(node: FreenetNode) -> Self {
        Self {
            node: Arc::new(RwLock::new(node)),
            content_store: Arc::new(ContentStore),
            local_addr: SocketAddr::from(([127, 0, 0, 1], 9481)),
            e2ee_enabled: false,
            encryptor: None,
        }
    }

    pub async fn start_node(&self) -> Result<()> {
        let mut node = self.node.write().await;
        node.start().await
    }

    pub fn enable_e2ee(&mut self, prekey_bundle: vigilnet_crypto::PreKeyBundle) -> Result<()> {
        let identity_key = vigilnet_crypto::IdentityKeyPair::generate();
        self.encryptor = Some(
            vigilnet_crypto::e2ee::DoubleRatchet::new_alice(
                identity_key,
                prekey_bundle,
            )
            .map_err(|e| FreenetError::E2eeError(e.to_string()))?
        );
        self.e2ee_enabled = true;
        info!("Freenet E2EE enabled");
        Ok(())
    }

    pub async fn insert_content(&self, data: &[u8], mime_type: &str) -> Result<ContentKey> {
        ContentStore::insert(data, mime_type).await
    }

    pub async fn get_content(&self, key: &ContentKey) -> Result<Vec<u8>> {
        ContentStore::get(key).await
    }

    pub fn node_state(&self) -> NodeState {
        self.node.blocking_read().state()
    }
}

#[async_trait]
impl vigilnet_agent_transport::AgentTransport for FreenetTransport {
    async fn bind(&mut self) -> vigilnet_agent_transport::TransportResult<()> {
        self.start_node().await
            .map_err(|e| vigilnet_agent_transport::TransportError::Bind(e.to_string()))?;
        
        info!("Freenet transport bound");
        Ok(())
    }

    async fn connect(&self, addr: SocketAddr) -> vigilnet_agent_transport::TransportResult<Box<dyn vigilnet_agent_transport::AgentConnection>> {
        warn!("Freenet is a store-and-forward network, not direct connections");
        Err(vigilnet_agent_transport::TransportError::ConnectionFailed(
            "Freenet uses content-based addressing, not socket connections".into()
        ))
    }

    async fn accept(&self) -> vigilnet_agent_transport::TransportResult<Box<dyn vigilnet_agent_transport::AgentConnection>> {
        warn!("Freenet doesn't support accept");
        Err(vigilnet_agent_transport::TransportError::NotAvailable(
            "Freenet uses content-based addressing".into()
        ))
    }

    async fn shutdown(&mut self) -> vigilnet_agent_transport::TransportResult<()> {
        let mut node = self.node.write().await;
        node.stop().await;
        info!("Freenet transport shutdown");
        Ok(())
    }

    fn transport_kind(&self) -> vigilnet_agent_transport::TransportKind {
        vigilnet_agent_transport::TransportKind::Freenet
    }

    fn local_addr(&self) -> vigilnet_agent_transport::TransportResult<SocketAddr> {
        Ok(self.local_addr)
    }
}
