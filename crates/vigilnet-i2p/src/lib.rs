//! VigilNet I2P
//!
//! I2P network integration via the SAM 3.1 protocol or embedded emissary router.
//! Provides garlic routing, tunnel management, and eepsite access.

pub mod sam;
pub mod tunnel;
pub mod naming;

use async_trait::async_trait;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

pub use sam::{SamClient, SessionType};
pub use tunnel::{TunnelConfig, TunnelDirection, TunnelPool};
pub use naming::NamingService;

#[derive(Debug, thiserror::Error)]
pub enum I2pError {
    #[error("SAM bridge connection failed: {0}")]
    SamConnectionFailed(String),

    #[error("Tunnel creation failed: {0}")]
    TunnelFailed(String),

    #[error("I2P destination not found: {0}")]
    DestinationNotFound(String),

    #[error("Naming service error: {0}")]
    NamingError(String),

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

pub type Result<T> = std::result::Result<T, I2pError>;

pub struct I2pTransport {
    sam_client: Arc<RwLock<SamClient>>,
    tunnel_pool: Arc<RwLock<TunnelPool>>,
    naming_service: Arc<RwLock<NamingService>>,
    local_addr: SocketAddr,
    e2ee_enabled: bool,
    encryptor: Option<vigilnet_crypto::e2ee::DoubleRatchet>,
    destination: Option<String>,
}

impl I2pTransport {
    pub fn new(sam_client: SamClient) -> Self {
        Self {
            sam_client: Arc::new(RwLock::new(sam_client)),
            tunnel_pool: Arc::new(RwLock::new(TunnelPool::new())),
            naming_service: Arc::new(RwLock::new(NamingService::new())),
            local_addr: SocketAddr::from(([127, 0, 0, 1], 7656)),
            e2ee_enabled: false,
            encryptor: None,
            destination: None,
        }
    }

    pub fn with_tunnel_pool(mut self, pool: TunnelPool) -> Self {
        self.tunnel_pool = Arc::new(RwLock::new(pool));
        self
    }

    pub fn with_naming_service(mut self, service: NamingService) -> Self {
        self.naming_service = Arc::new(RwLock::new(service));
        self
    }

    pub async fn connect_sam(&mut self) -> Result<()> {
        let mut client = self.sam_client.write().await;
        client.connect().await?;
        self.destination = client.destination().map(String::from);
        info!("Connected to I2P SAM bridge");
        Ok(())
    }

    pub async fn create_session(&mut self, session_type: SessionType, nickname: &str) -> Result<String> {
        let mut client = self.sam_client.write().await;
        let session_id = client.create_session(session_type, nickname).await?;
        self.destination = client.destination().map(String::from);
        info!("Created I2P session: {}", session_id);
        Ok(session_id)
    }

    pub fn enable_e2ee(&mut self, prekey_bundle: vigilnet_crypto::PreKeyBundle) -> Result<()> {
        let identity_key = vigilnet_crypto::IdentityKeyPair::generate();
        self.encryptor = Some(
            vigilnet_crypto::e2ee::DoubleRatchet::new_alice(
                identity_key,
                prekey_bundle,
            )
            .map_err(|e| I2pError::E2eeError(e.to_string()))?
        );
        self.e2ee_enabled = true;
        info!("I2P E2EE enabled");
        Ok(())
    }

    pub async fn lookup_destination(&self, hostname: &str) -> Result<String> {
        let naming = self.naming_service.read().await;
        
        if let Some(dest) = naming.lookup(hostname) {
            return Ok(dest.to_string());
        }
        
        drop(naming);
        let client = self.sam_client.read().await;
        client.naming_lookup(hostname).await
    }

    pub fn destination(&self) -> Option<&str> {
        self.destination.as_deref()
    }
}

pub struct I2pStreamConnection {
    stream: tokio::net::tcp::OwnedReadHalf,
    e2ee_enabled: bool,
    encryptor: Option<vigilnet_crypto::e2ee::DoubleRatchet>,
}

impl I2pStreamConnection {
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        let payload = if self.e2ee_enabled {
            if let Some(ref mut enc) = self.encryptor {
                let encrypted = enc.encrypt_message(data)
                    .map_err(|e| I2pError::E2eeError(e.to_string()))?;
                encrypted.into_bytes()
            } else {
                data.to_vec()
            }
        } else {
            data.to_vec()
        };

        use tokio::io::AsyncWriteExt;
        let mut stream = self.stream.try_clone().await?;
        stream.write_all(&payload).await
            .map_err(|e| I2pError::SendError(e.to_string()))
    }

    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        use tokio::io::AsyncReadExt;
        let n = self.stream.read(buf).await
            .map_err(|e| I2pError::RecvError(e.to_string()))?;
        
        if self.e2ee_enabled && n > 0 {
            if let Some(ref mut enc) = self.encryptor {
                let decrypted = enc.decrypt_message(&buf[..n])
                    .map_err(|e| I2pError::E2eeError(e.to_string()))?;
                buf[..decrypted.len()].copy_from_slice(&decrypted);
                return Ok(decrypted.len());
            }
        }
        
        Ok(n)
    }
}

#[async_trait]
impl vigilnet_agent_transport::AgentTransport for I2pTransport {
    async fn bind(&mut self) -> vigilnet_agent_transport::TransportResult<()> {
        self.connect_sam().await
            .map_err(|e| vigilnet_agent_transport::TransportError::Bind(e.to_string()))?;
        
        self.create_session(SessionType::Stream, "vigilnet").await
            .map_err(|e| vigilnet_agent_transport::TransportError::Bind(e.to_string()))?;
        
        info!("I2P transport bound");
        Ok(())
    }

    async fn connect(&self, addr: SocketAddr) -> vigilnet_agent_transport::TransportResult<Box<dyn vigilnet_agent_transport::AgentConnection>> {
        let host = addr.ip().to_string();
        let port = addr.port();
        
        let client = self.sam_client.read().await;
        
        let stream = client.stream_connect(&host).await
            .map_err(|e| vigilnet_agent_transport::TransportError::ConnectionFailed(e.to_string()))?;
        
        let (reader, writer) = stream.into_split();
        
        Ok(Box::new(I2pAgentConnection {
            reader: Arc::new(RwLock::new(reader)),
            writer: Arc::new(RwLock::new(writer)),
            remote_addr: addr,
        }))
    }

    async fn accept(&self) -> vigilnet_agent_transport::TransportResult<Box<dyn vigilnet_agent_transport::AgentConnection>> {
        warn!("I2P accept not implemented - use stream connect");
        Err(vigilnet_agent_transport::TransportError::NotAvailable("Use stream connect".into()))
    }

    async fn shutdown(&mut self) -> vigilnet_agent_transport::TransportResult<()> {
        let mut client = self.sam_client.write().await;
        client.close().await;
        info!("I2P transport shutdown");
        Ok(())
    }

    fn transport_kind(&self) -> vigilnet_agent_transport::TransportKind {
        vigilnet_agent_transport::TransportKind::I2p
    }

    fn local_addr(&self) -> vigilnet_agent_transport::TransportResult<SocketAddr> {
        Ok(self.local_addr)
    }
}

pub struct I2pAgentConnection {
    reader: Arc<RwLock<tokio::net::tcp::OwnedReadHalf>>,
    writer: Arc<RwLock<tokio::net::tcp::OwnedWriteHalf>>,
    remote_addr: SocketAddr,
}

#[async_trait]
impl vigilnet_agent_transport::AgentConnection for I2pAgentConnection {
    async fn send(&self, data: Bytes) -> vigilnet_agent_transport::TransportResult<()> {
        use tokio::io::AsyncWriteExt;
        let mut writer = self.writer.write().await;
        writer.write_all(&data).await
            .map_err(|e| vigilnet_agent_transport::TransportError::Send(e.to_string()))
    }

    async fn recv(&self) -> vigilnet_agent_transport::TransportResult<Bytes> {
        use tokio::io::AsyncReadExt;
        let mut reader = self.reader.write().await;
        let mut buf = vec![0u8; 65536];
        let n = reader.read(&mut buf).await
            .map_err(|e| vigilnet_agent_transport::TransportError::Recv(e.to_string()))?;
        Ok(Bytes::from(buf[..n].to_vec()))
    }

    fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    fn transport_kind(&self) -> vigilnet_agent_transport::TransportKind {
        vigilnet_agent_transport::TransportKind::I2p
    }

    async fn close(&self) -> vigilnet_agent_transport::TransportResult<()> {
        Ok(())
    }
}
