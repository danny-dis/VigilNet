//! High-speed connection pooling for VigilNet agents using QUIC

use crate::agent::{AgentId, AgentInfo};
use crate::message::{Message, MessageSerializer, Result as MessageResult};
use anyhow::Result as AnyhowResult;
use parking_lot::RwLock;
use quinn::{
    ClientConfig, Connection, Endpoint, EndpointConfig,
    TransportConfig, VarInt,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, info, instrument, warn};
use vigilnet_crypto::{
    IdentityKeyPair, OneTimePreKey, PreKeyBundle, Session, SessionMessage, SignedPreKey,
};

/// Connection state
#[derive(Debug, Clone)]
pub enum ConnectionState {
    Connecting,
    Connected,
    Disconnected,
    Failed(String),
}

/// Connection metadata
pub struct ConnectionMeta {
    pub peer_id: AgentId,
    pub remote_addr: SocketAddr,
    pub state: ConnectionState,
    pub latency_ns: u64,
    pub created_at: Instant,
    pub last_active: Instant,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl ConnectionMeta {
    pub fn new(peer_id: AgentId, remote_addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            peer_id,
            remote_addr,
            state: ConnectionState::Connecting,
            latency_ns: 0,
            created_at: now,
            last_active: now,
            messages_sent: 0,
            messages_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
}

/// Connection handle for sending/receiving messages
pub struct PooledConnection {
    pub meta: Arc<RwLock<ConnectionMeta>>,
    connection: Connection,
    sender: mpsc::Sender<Message>,
}

impl PooledConnection {
    pub async fn send(&self, message: Message) -> AnyhowResult<()> {
        let serializer = MessageSerializer::new();
        let data = serializer.serialize_message(&message)?;

        {
            let mut meta = self.meta.write();
            meta.last_active = Instant::now();
            meta.messages_sent += 1;
            meta.bytes_sent += data.len() as u64;
        }

        let mut stream = self.connection.open_uni().await?;
        stream.write_all(&data).await?;
        stream.finish().await?;

        debug!(
            peer_id = %self.meta.read().peer_id,
            size = data.len(),
            "Message sent"
        );
        Ok(())
    }

    pub fn update_latency(&self, latency_ns: u64) {
        let mut meta = self.meta.write();
        meta.latency_ns = latency_ns;
    }

    pub fn get_latency(&self) -> u64 {
        self.meta.read().latency_ns
    }
}

/// Connection pool configuration
#[derive(Debug, Clone)]
pub struct ConnectionPoolConfig {
    pub max_connections: usize,
    pub connection_timeout: Duration,
    pub idle_timeout: Duration,
    pub keep_alive_interval: Duration,
    pub max_idle_timeout: Duration,
    pub connect_timeout: Duration,
    pub warmup_connections: usize,
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 100,
            connection_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(60),
            keep_alive_interval: Duration::from_secs(10),
            max_idle_timeout: Duration::from_secs(120),
            connect_timeout: Duration::from_secs(10),
            warmup_connections: 3,
        }
    }
}

/// Connection pool for managing peer connections
pub struct ConnectionPool {
    config: ConnectionPoolConfig,
    endpoint: Endpoint,
    connections: RwLock<HashMap<AgentId, Arc<PooledConnection>>>,
    pending_connects: RwLock<HashMap<AgentId, mpsc::Sender<AnyhowResult<Arc<PooledConnection>>>>>,
    sessions: RwLock<HashMap<AgentId, Session>>,
    identity_key: Option<IdentityKeyPair>,
    signed_prekey: Option<SignedPreKey>,
    one_time_prekeys: RwLock<Vec<OneTimePreKey>>,
}

impl ConnectionPool {
    #[instrument(skip(self))]
    pub async fn new(config: ConnectionPoolConfig) -> AnyhowResult<Self> {
        let endpoint = Self::create_endpoint(&config).await?;

        info!(
            max_connections = config.max_connections,
            "Connection pool initialized"
        );

        Ok(Self {
            config,
            endpoint,
            connections: RwLock::new(HashMap::new()),
            pending_connects: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
            identity_key: None,
            signed_prekey: None,
            one_time_prekeys: RwLock::new(Vec::new()),
        })
    }

    pub fn with_identity_key(mut self, identity_key: IdentityKeyPair) -> Self {
        self.identity_key = Some(identity_key);
        self
    }

    pub fn with_signed_prekey(mut self, signed_prekey: SignedPreKey) -> Self {
        self.signed_prekey = Some(signed_prekey);
        self
    }

    pub fn with_one_time_prekeys(mut self, prekeys: Vec<OneTimePreKey>) -> Self {
        self.one_time_prekeys = RwLock::new(prekeys);
        self
    }

    pub fn generate_identity_keys(&mut self) {
        let identity_key = IdentityKeyPair::generate();
        let signed_prekey = SignedPreKey::generate(&identity_key, 1);
        
        let mut otpks = Vec::new();
        for i in 0..100 {
            otpks.push(OneTimePreKey::generate(i));
        }

        self.identity_key = Some(identity_key);
        self.signed_prekey = Some(signed_prekey);
        self.one_time_prekeys = RwLock::new(otpks);
    }

    pub fn get_prekey_bundle(&self) -> Option<PreKeyBundle> {
        let identity_key = self.identity_key.as_ref()?;
        let signed_prekey = self.signed_prekey.as_ref()?;
        let mut otpk = self.one_time_prekeys.write().pop();

        Some(PreKeyBundle {
            identity_key: identity_key.identity_public,
            signed_prekey: signed_prekey.clone(),
            one_time_prekey: otpk.take(),
        })
    }

    pub fn create_session(&mut self, peer_id: &AgentId, bundle: &PreKeyBundle) -> AnyhowResult<()> {
        let peer_identity: [u8; 32] = peer_id.to_bytes();

        let (session, _) = Session::create_initiator(bundle, peer_identity)
            .map_err(|e| anyhow::anyhow!("Failed to create session: {}", e))?;

        self.sessions.write().insert(peer_id.clone(), session);
        
        info!(peer_id = %peer_id, "E2EE session created");
        Ok(())
    }

    pub fn get_session(&self, peer_id: &AgentId) -> Option<Session> {
        self.sessions.read().get(peer_id).cloned()
    }

    pub fn has_session(&self, peer_id: &AgentId) -> bool {
        self.sessions.read().contains_key(peer_id)
    }

    pub fn remove_session(&self, peer_id: &AgentId) {
        self.sessions.write().remove(peer_id);
    }

    pub fn process_prekey_message(
        &mut self,
        peer_id: &AgentId,
        message: &SessionMessage,
    ) -> AnyhowResult<Vec<u8>> {
        let identity_key = self.identity_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Identity key not configured"))?;
        let signed_prekey = self.signed_prekey.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signed prekey not configured"))?;

        let (initiator_identity, ephemeral_key, spk_id, otpk_id) = match &message.message_type {
            vigilnet_crypto::MessageType::X3DHPreKey {
                identity_key,
                ephemeral_key,
                spk_id,
                otpk_id,
            } => (*identity_key, *ephemeral_key, *spk_id, *otpk_id),
            _ => return Err(anyhow::anyhow!("Not a prekey message")),
        };

        let otpk = if let Some(_otpk_id) = otpk_id {
            self.one_time_prekeys.write().pop()
        } else {
            None
        };

        let mut session = Session::create_responder(
            identity_key,
            signed_prekey,
            otpk.as_ref(),
            initiator_identity,
            ephemeral_key,
            spk_id,
            otpk_id,
        ).map_err(|e| anyhow::anyhow!("Failed to create responder session: {}", e))?;

        let plaintext = session.decrypt(message)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt: {}", e))?;

        self.sessions.write().insert(peer_id.clone(), session);

        Ok(plaintext)
    }

    pub fn encrypt_message(&mut self, peer_id: &AgentId, plaintext: &[u8]) -> AnyhowResult<SessionMessage> {
        let mut sessions = self.sessions.write();
        let session = sessions.get_mut(peer_id)
            .ok_or_else(|| anyhow::anyhow!("No session for peer: {}", peer_id))?;

        let encrypted = session.encrypt(plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        Ok(encrypted)
    }

    pub fn decrypt_message(&mut self, peer_id: &AgentId, message: &SessionMessage) -> AnyhowResult<Vec<u8>> {
        let mut sessions = self.sessions.write();
        let session = sessions.get_mut(peer_id)
            .ok_or_else(|| anyhow::anyhow!("No session for peer: {}", peer_id))?;

        let plaintext = session.decrypt(message)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        Ok(plaintext)
    }

    pub fn get_all_sessions(&self) -> Vec<AgentId> {
        self.sessions.read().keys().cloned().collect()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.read().len()
    }

    async fn create_endpoint(config: &ConnectionPoolConfig) -> AnyhowResult<Endpoint> {
        let mut endpoint_config = EndpointConfig::default();
        endpoint_config
            .transport_config(Arc::new(Self::create_transport_config(config)?));

        let runtime = tokio::runtime::Handle::current();
        let endpoint = Endpoint::server(endpoint_config, "0.0.0.0:0".parse()?, runtime)?;

        Ok(endpoint)
    }

    fn create_transport_config(config: &ConnectionPoolConfig) -> AnyhowResult<TransportConfig> {
        let mut transport = TransportConfig::default();
        transport.max_idle_timeout(Some(VarInt::from_u64(
            config.max_idle_timeout.as_millis() as u64,
        )?));
        transport.keep_alive_interval(Some(config.keep_alive_interval));
        transport.max_concurrent_bidi_streams(VarInt::from_u64(100)?);
        transport.max_concurrent_uni_streams(VarInt::from_u64(100)?);
        Ok(transport)
    }

    #[instrument(skip(self, addr))]
    pub async fn connect(&self, peer_id: AgentId, addr: SocketAddr) -> AnyhowResult<Arc<PooledConnection>> {
        if let Some(existing) = self.connections.read().get(&peer_id) {
            debug!(peer_id = %peer_id, "Using existing connection");
            return Ok(existing.clone());
        }

        if let Some(pending) = self.pending_connects.read().get(&peer_id) {
            let (tx, rx) = mpsc::channel(1);
            pending.send(rx).await.ok();
            return rx.await.unwrap();
        }

        let (tx, rx) = mpsc::channel(1);
        self.pending_connects.write().insert(peer_id.clone(), tx);

        let client_config = self.create_client_config()?;
        let connection = self.endpoint.connect_with(client_config, addr, "vigilnet")?;

        let conn = tokio::time::timeout(self.config.connect_timeout, connection)
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

        let pooled = Arc::new(PooledConnection {
            meta: Arc::new(RwLock::new(ConnectionMeta::new(peer_id.clone(), addr))),
            connection: conn,
            sender: mpsc::channel(100).0,
        });

        {
            let mut meta = pooled.meta.write();
            meta.state = ConnectionState::Connected;
        }

        self.connections.write().insert(peer_id.clone(), pooled.clone());
        self.pending_connects.write().remove(&peer_id);

        info!(peer_id = %peer_id, remote_addr = %addr, "New connection established");

        Ok(pooled)
    }

    fn create_client_config(&self) -> AnyhowResult<ClientConfig> {
        let mut transport = TransportConfig::default();
        transport.max_idle_timeout(Some(VarInt::from_u64(
            self.config.max_idle_timeout.as_millis() as u64,
        )?));
        transport.keep_alive_interval(Some(self.config.keep_alive_interval));

        let mut client_config = ClientConfig::new(Arc::new(transport));
        client_config.enable_keylog();

        Ok(client_config)
    }

    pub async fn disconnect(&self, peer_id: &AgentId) -> AnyhowResult<()> {
        if let Some(conn) = self.connections.write().remove(peer_id) {
            let mut meta = conn.meta.write();
            meta.state = ConnectionState::Disconnected;
            info!(peer_id = %peer_id, "Disconnected");
        }
        Ok(())
    }

    pub fn get(&self, peer_id: &AgentId) -> Option<Arc<PooledConnection>> {
        self.connections.read().get(peer_id).cloned()
    }

    pub fn is_connected(&self, peer_id: &AgentId) -> bool {
        self.connections
            .read()
            .get(peer_id)
            .map(|c| matches!(c.meta.read().state, ConnectionState::Connected))
            .unwrap_or(false)
    }

    pub fn get_all_connected(&self) -> Vec<AgentId> {
        self.connections
            .read()
            .iter()
            .filter(|(_, c)| matches!(c.meta.read().state, ConnectionState::Connected))
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub fn connection_count(&self) -> usize {
        self.connections.read().len()
    }

    pub async fn warmup_connections(&self, agents: &[AgentInfo]) -> AnyhowResult<()> {
        let warmup_count = self.config.warmup_connections.min(agents.len());

        let mut handles = Vec::new();
        for agent in agents.iter().take(warmup_count) {
            if let Some(addr) = self.resolve_agent_address(agent) {
                let pool = Arc::new(self.clone());
                let peer_id = agent.id.clone();
                let handle = tokio::spawn(async move {
                    pool.connect(peer_id, addr).await
                });
                handles.push(handle);
            }
        }

        for handle in handles {
            if let Err(e) = handle.await {
                warn!(error = %e, "Warmup connection failed");
            }
        }

        info!(count = warmup_count, "Connection warmup complete");
        Ok(())
    }

    fn resolve_agent_address(&self, agent: &AgentInfo) -> Option<SocketAddr> {
        None
    }

    pub async fn measure_latency(&self, peer_id: &AgentId) -> AnyhowResult<u64> {
        let conn = self
            .get(peer_id)
            .ok_or_else(|| anyhow::anyhow!("Not connected to {}", peer_id))?;

        let start = Instant::now();
        let ping = Message::new(
            [0u8; 8],
            0,
            0,
            vec![],
            crate::message::MessageType::Heartbeat,
        );
        conn.send(ping).await?;

        let elapsed = start.elapsed().as_nanos() as u64;
        conn.update_latency(elapsed);

        Ok(elapsed)
    }

    pub fn get_connection_stats(&self, peer_id: &AgentId) -> Option<ConnectionMeta> {
        self.connections
            .read()
            .get(peer_id)
            .map(|c| c.meta.read().clone())
    }
}

impl Clone for ConnectionPool {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            endpoint: self.endpoint.clone(),
            connections: RwLock::new(HashMap::new()),
            pending_connects: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
            identity_key: self.identity_key.clone(),
            signed_prekey: self.signed_prekey.clone(),
            one_time_prekeys: RwLock::new(Vec::new()),
        }
    }
}

/// Connection pool error types
#[derive(Debug, thiserror::Error)]
pub enum ConnectionPoolError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Not connected: {0}")]
    NotConnected(String),

    #[error("Pool full")]
    PoolFull,

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("E2EE error: {0}")]
    E2EEError(String),

    #[error("No session: {0}")]
    NoSession(String),
}

pub type PoolResult<T> = std::result::Result<T, ConnectionPoolError>;
