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
use tracing::{debug, error, info, instrument, trace, warn};
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
    #[instrument(skip(self, message), level = "debug")]
    pub async fn send(&self, message: Message) -> AnyhowResult<()> {
        let peer_id = self.meta.read().peer_id.clone();
        trace!(peer_id = %peer_id, "Serializing message");

        let serializer = MessageSerializer::new();
        let data = serializer.serialize_message(&message)?;

        {
            let mut meta = self.meta.write();
            meta.last_active = Instant::now();
            meta.messages_sent += 1;
            meta.bytes_sent += data.len() as u64;
        }

        trace!(peer_id = %peer_id, data_len = data.len(), "Opening QUIC stream");
        let mut stream = self.connection.open_uni().await?;
        stream.write_all(&data).await?;
        stream.finish().await?;

        debug!(
            peer_id = %peer_id,
            bytes_sent = data.len(),
            total_messages = self.meta.read().messages_sent,
            "Message sent successfully"
        );
        Ok(())
    }

    #[instrument(skip(self), level = "trace")]
    pub fn update_latency(&self, latency_ns: u64) {
        let peer_id = self.meta.read().peer_id.clone();
        trace!(peer_id = %peer_id, latency_ns, "Updating connection latency");
        let mut meta = self.meta.write();
        meta.latency_ns = latency_ns;
    }

    #[instrument(skip(self), level = "trace")]
    pub fn get_latency(&self) -> u64 {
        let latency = self.meta.read().latency_ns;
        trace!(latency_ns = latency, "Retrieving connection latency");
        latency
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
    #[instrument(skip(config), level = "info")]
    pub async fn new(config: ConnectionPoolConfig) -> AnyhowResult<Self> {
        trace!("Creating QUIC endpoint");
        let endpoint = Self::create_endpoint(&config).await?;

        info!(
            max_connections = config.max_connections,
            connect_timeout_secs = config.connect_timeout.as_secs(),
            idle_timeout_secs = config.idle_timeout.as_secs(),
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

    #[instrument(skip(self), level = "info")]
    pub fn generate_identity_keys(&mut self) {
        trace!("Generating identity key pair");
        let identity_key = IdentityKeyPair::generate();

        trace!("Generating signed prekey");
        let signed_prekey = SignedPreKey::generate(&identity_key, 1);

        trace!("Generating one-time prekeys");
        let mut otpks = Vec::new();
        for i in 0..100 {
            otpks.push(OneTimePreKey::generate(i));
        }

        self.identity_key = Some(identity_key);
        self.signed_prekey = Some(signed_prekey);
        self.one_time_prekeys = RwLock::new(otpks);

        info!(prekeys_generated = 100, "Identity keys generated");
    }

    #[instrument(skip(self), level = "debug")]
    pub fn get_prekey_bundle(&self) -> Option<PreKeyBundle> {
        let identity_key = self.identity_key.as_ref()?;
        let signed_prekey = self.signed_prekey.as_ref()?;
        let mut otpk = self.one_time_prekeys.write().pop();

        let remaining_prekeys = self.one_time_prekeys.read().len();
        debug!(
            has_one_time_prekey = otpk.is_some(),
            remaining_prekeys,
            "Generated prekey bundle"
        );

        Some(PreKeyBundle {
            identity_key: identity_key.identity_public,
            signed_prekey: signed_prekey.clone(),
            one_time_prekey: otpk.take(),
        })
    }

    #[instrument(skip(self, bundle), level = "info")]
    pub fn create_session(&mut self, peer_id: &AgentId, bundle: &PreKeyBundle) -> AnyhowResult<()> {
        info!(peer_id = %peer_id, "Creating E2EE session");
        let peer_identity: [u8; 32] = peer_id.to_bytes();

        trace!("Creating initiator session");
        let (session, _) = Session::create_initiator(bundle, peer_identity)
            .map_err(|e| {
                error!(error = %e, "Failed to create initiator session");
                anyhow::anyhow!("Failed to create session: {}", e)
            })?;

        self.sessions.write().insert(peer_id.clone(), session);
        let session_count = self.sessions.read().len();

        info!(
            peer_id = %peer_id,
            total_sessions = session_count,
            "E2EE session created successfully"
        );
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

    #[instrument(skip(self, plaintext), level = "debug")]
    pub fn encrypt_message(&mut self, peer_id: &AgentId, plaintext: &[u8]) -> AnyhowResult<SessionMessage> {
        trace!(peer_id = %peer_id, plaintext_len = plaintext.len(), "Encrypting message");

        let mut sessions = self.sessions.write();
        let session = sessions.get_mut(peer_id)
            .ok_or_else(|| {
                error!(peer_id = %peer_id, "No session found for peer");
                anyhow::anyhow!("No session for peer: {}", peer_id)
            })?;

        let encrypted = session.encrypt(plaintext)
            .map_err(|e| {
                error!(error = %e, "Encryption failed");
                anyhow::anyhow!("Encryption failed: {}", e)
            })?;

        trace!("Message encrypted successfully");
        Ok(encrypted)
    }

    #[instrument(skip(self, message), level = "debug")]
    pub fn decrypt_message(&mut self, peer_id: &AgentId, message: &SessionMessage) -> AnyhowResult<Vec<u8>> {
        trace!(peer_id = %peer_id, "Decrypting message");

        let mut sessions = self.sessions.write();
        let session = sessions.get_mut(peer_id)
            .ok_or_else(|| {
                error!(peer_id = %peer_id, "No session found for peer");
                anyhow::anyhow!("No session for peer: {}", peer_id)
            })?;

        let plaintext = session.decrypt(message)
            .map_err(|e| {
                error!(error = %e, "Decryption failed");
                anyhow::anyhow!("Decryption failed: {}", e)
            })?;

        trace!(plaintext_len = plaintext.len(), "Message decrypted successfully");
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

    #[instrument(skip(self, addr), level = "info")]
    pub async fn connect(&self, peer_id: AgentId, addr: SocketAddr) -> AnyhowResult<Arc<PooledConnection>> {
        info!(peer_id = %peer_id, remote_addr = %addr, "Attempting connection");

        // Check for existing connection
        if let Some(existing) = self.connections.read().get(&peer_id) {
            debug!(peer_id = %peer_id, "Using existing connection");
            return Ok(existing.clone());
        }

        // Check for pending connection
        if let Some(pending) = self.pending_connects.read().get(&peer_id) {
            trace!(peer_id = %peer_id, "Connection pending, waiting...");
            let (tx, rx) = mpsc::channel(1);
            if let Err(e) = pending.send(rx).await {
                error!(error = %e, "Failed to queue for pending connection");
            }
            return rx.await.map_err(|e| {
                error!(error = %e, "Pending connection channel closed");
                anyhow::anyhow!("Pending connection channel closed: {}", e)
            })?;
        }

        trace!("Creating pending connection channel");
        let (tx, rx) = mpsc::channel(1);
        self.pending_connects.write().insert(peer_id.clone(), tx);

        trace!("Creating QUIC client configuration");
        let client_config = self.create_client_config()?;

        trace!("Initiating QUIC connection");
        let connection = self.endpoint.connect_with(client_config, addr, "vigilnet")
            .map_err(|e| {
                error!(error = %e, "Failed to initiate QUIC connection");
                e
            })?;

        trace!("Awaiting connection with timeout");
        let conn = tokio::time::timeout(self.config.connect_timeout, connection)
            .await
            .map_err(|_| {
                error!(timeout_secs = self.config.connect_timeout.as_secs(), "Connection timed out");
                anyhow::anyhow!("Connection timeout")
            })??;

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

        let connection_count = self.connections.read().len();
        info!(
            peer_id = %peer_id,
            remote_addr = %addr,
            total_connections = connection_count,
            "New connection established successfully"
        );

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

    #[instrument(skip(self), level = "info")]
    pub async fn disconnect(&self, peer_id: &AgentId) -> AnyhowResult<()> {
        info!(peer_id = %peer_id, "Disconnecting peer");

        if let Some(conn) = self.connections.write().remove(peer_id) {
            let mut meta = conn.meta.write();
            meta.state = ConnectionState::Disconnected;
            let connection_count = self.connections.read().len();
            info!(
                peer_id = %peer_id,
                remaining_connections = connection_count,
                "Peer disconnected"
            );
        } else {
            warn!(peer_id = %peer_id, "Attempted to disconnect unknown peer");
        }
        Ok(())
    }

    #[instrument(skip(self), level = "trace")]
    pub fn get(&self, peer_id: &AgentId) -> Option<Arc<PooledConnection>> {
        let conn = self.connections.read().get(peer_id).cloned();
        trace!(peer_id = %peer_id, found = conn.is_some(), "Retrieving connection");
        conn
    }

    #[instrument(skip(self), level = "trace")]
    pub fn is_connected(&self, peer_id: &AgentId) -> bool {
        let connected = self.connections
            .read()
            .get(peer_id)
            .map(|c| matches!(c.meta.read().state, ConnectionState::Connected))
            .unwrap_or(false);
        trace!(peer_id = %peer_id, connected, "Checked connection status");
        connected
    }

    #[instrument(skip(self), level = "debug")]
    pub fn get_all_connected(&self) -> Vec<AgentId> {
        let connected: Vec<_> = self.connections
            .read()
            .iter()
            .filter(|(_, c)| matches!(c.meta.read().state, ConnectionState::Connected))
            .map(|(id, _)| id.clone())
            .collect();
        debug!(connected_count = connected.len(), "Retrieved all connected peers");
        connected
    }

    #[instrument(skip(self), level = "trace")]
    pub fn connection_count(&self) -> usize {
        let count = self.connections.read().len();
        trace!(connection_count = count, "Retrieving connection count");
        count
    }

    #[instrument(skip(self, agents), level = "info")]
    pub async fn warmup_connections(&self, agents: &[AgentInfo]) -> AnyhowResult<()> {
        let warmup_count = self.config.warmup_connections.min(agents.len());
        info!(
            total_agents = agents.len(),
            warmup_count,
            "Starting connection warmup"
        );

        let mut handles = Vec::new();
        let mut resolved_count = 0;

        for agent in agents.iter().take(warmup_count) {
            if let Some(addr) = self.resolve_agent_address(agent) {
                trace!(
                    peer_id = %agent.id,
                    addr = %addr,
                    "Spawning warmup connection task"
                );
                let pool = Arc::new(self.clone());
                let peer_id = agent.id.clone();
                let handle = tokio::spawn(async move {
                    pool.connect(peer_id, addr).await
                });
                handles.push(handle);
                resolved_count += 1;
            } else {
                warn!(peer_id = %agent.id, "Could not resolve address for agent");
            }
        }

        let mut success_count = 0;
        let mut failure_count = 0;

        for handle in handles {
            match handle.await {
                Ok(Ok(_)) => {
                    trace!("Warmup connection succeeded");
                    success_count += 1;
                }
                Ok(Err(e)) => {
                    warn!(error = %e, "Warmup connection failed");
                    failure_count += 1;
                }
                Err(e) => {
                    error!(error = %e, "Warmup connection task panicked");
                    failure_count += 1;
                }
            }
        }

        info!(
            success_count,
            failure_count,
            resolved_count,
            "Connection warmup complete"
        );
        Ok(())
    }

    fn resolve_agent_address(&self, agent: &AgentInfo) -> Option<SocketAddr> {
        None
    }

    #[instrument(skip(self), level = "debug")]
    pub async fn measure_latency(&self, peer_id: &AgentId) -> AnyhowResult<u64> {
        trace!(peer_id = %peer_id, "Measuring connection latency");

        let conn = self
            .get(peer_id)
            .ok_or_else(|| {
                error!(peer_id = %peer_id, "Not connected to peer");
                anyhow::anyhow!("Not connected to {}", peer_id)
            })?;

        let start = Instant::now();
        let ping = Message::new(
            [0u8; 8],
            0,
            0,
            vec![],
            crate::message::MessageType::Heartbeat,
        );

        trace!("Sending ping message");
        conn.send(ping).await?;

        let elapsed = start.elapsed().as_nanos() as u64;
        conn.update_latency(elapsed);

        debug!(
            peer_id = %peer_id,
            latency_ns = elapsed,
            "Latency measured"
        );

        Ok(elapsed)
    }

    #[instrument(skip(self), level = "debug")]
    pub fn get_connection_stats(&self, peer_id: &AgentId) -> Option<ConnectionMeta> {
        let stats = self.connections
            .read()
            .get(peer_id)
            .map(|c| c.meta.read().clone());

        if let Some(ref meta) = stats {
            debug!(
                peer_id = %peer_id,
                messages_sent = meta.messages_sent,
                messages_received = meta.messages_received,
                bytes_sent = meta.bytes_sent,
                bytes_received = meta.bytes_received,
                "Retrieved connection stats"
            );
        } else {
            trace!(peer_id = %peer_id, "No stats found for peer");
        }

        stats
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

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::PeerId;

    // ============================================
    // Unit Tests for Core Functionality
    // ============================================

    #[test]
    fn test_connection_pool_config_default() {
        let config = ConnectionPoolConfig::default();
        assert_eq!(config.max_connections, 100);
        assert_eq!(config.connection_timeout, Duration::from_secs(30));
        assert_eq!(config.idle_timeout, Duration::from_secs(60));
        assert_eq!(config.keep_alive_interval, Duration::from_secs(10));
        assert_eq!(config.max_idle_timeout, Duration::from_secs(120));
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
        assert_eq!(config.warmup_connections, 3);
    }

    #[test]
    fn test_connection_pool_config_custom() {
        let config = ConnectionPoolConfig {
            max_connections: 50,
            connection_timeout: Duration::from_secs(60),
            ..Default::default()
        };
        assert_eq!(config.max_connections, 50);
        assert_eq!(config.connection_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_connection_meta_creation() {
        let peer_id = AgentId::new(PeerId::random());
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let meta = ConnectionMeta::new(peer_id, addr);
        
        assert_eq!(meta.remote_addr, addr);
        matches!(meta.state, ConnectionState::Connecting);
        assert_eq!(meta.latency_ns, 0);
        assert_eq!(meta.messages_sent, 0);
        assert_eq!(meta.messages_received, 0);
    }

    #[test]
    fn test_connection_states() {
        let connecting = ConnectionState::Connecting;
        let connected = ConnectionState::Connected;
        let disconnected = ConnectionState::Disconnected;
        let failed = ConnectionState::Failed("test error".to_string());
        
        // Just verify they can be created and debug printed
        format!("{:?}", connecting);
        format!("{:?}", connected);
        format!("{:?}", disconnected);
        format!("{:?}", failed);
    }

    #[test]
    fn test_pool_error_variants() {
        let err1 = ConnectionPoolError::ConnectionFailed("conn failed".to_string());
        assert!(err1.to_string().contains("Connection failed"));
        
        let err2 = ConnectionPoolError::NotConnected("peer123".to_string());
        assert!(err2.to_string().contains("Not connected"));
        
        let err3 = ConnectionPoolError::PoolFull;
        assert!(err3.to_string().contains("Pool full"));
        
        let err4 = ConnectionPoolError::Timeout("timeout".to_string());
        assert!(err4.to_string().contains("Timeout"));
        
        let err5 = ConnectionPoolError::E2EEError("crypto error".to_string());
        assert!(err5.to_string().contains("E2EE error"));
        
        let err6 = ConnectionPoolError::NoSession("no session".to_string());
        assert!(err6.to_string().contains("No session"));
    }

    // ============================================
    // Session Management Tests
    // ============================================

    #[test]
    fn test_generate_identity_keys() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let mut pool = ConnectionPool::new(config).await.unwrap();
            
            pool.generate_identity_keys();
            
            assert!(pool.identity_key.is_some());
            assert!(pool.signed_prekey.is_some());
            assert_eq!(pool.one_time_prekeys.read().len(), 100);
        });
    }

    #[test]
    fn test_get_prekey_bundle() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let mut pool = ConnectionPool::new(config).await.unwrap();
            
            // Without keys, should return None
            assert!(pool.get_prekey_bundle().is_none());
            
            // After generating keys, should return Some
            pool.generate_identity_keys();
            let bundle = pool.get_prekey_bundle();
            assert!(bundle.is_some());
            
            // Should consume one prekey
            assert_eq!(pool.one_time_prekeys.read().len(), 99);
        });
    }

    #[test]
    fn test_has_session() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let pool = ConnectionPool::new(config).await.unwrap();
            let peer_id = AgentId::new(PeerId::random());
            
            assert!(!pool.has_session(&peer_id));
            assert_eq!(pool.session_count(), 0);
        });
    }

    #[test]
    fn test_remove_session() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let pool = ConnectionPool::new(config).await.unwrap();
            let peer_id = AgentId::new(PeerId::random());
            
            // Should not panic when removing non-existent session
            pool.remove_session(&peer_id);
        });
    }

    #[test]
    fn test_get_all_sessions_empty() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let pool = ConnectionPool::new(config).await.unwrap();
            
            let sessions = pool.get_all_sessions();
            assert!(sessions.is_empty());
        });
    }

    // ============================================
    // Connection Management Tests
    // ============================================

    #[test]
    fn test_pool_clone() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let pool = ConnectionPool::new(config).await.unwrap();
            
            let cloned = pool.clone();
            assert_eq!(cloned.connection_count(), 0);
            assert!(cloned.get(&AgentId::new(PeerId::random())).is_none());
        });
    }

    #[test]
    fn test_is_connected_nonexistent() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let pool = ConnectionPool::new(config).await.unwrap();
            let peer_id = AgentId::new(PeerId::random());
            
            assert!(!pool.is_connected(&peer_id));
        });
    }

    #[test]
    fn test_get_nonexistent_connection() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let pool = ConnectionPool::new(config).await.unwrap();
            let peer_id = AgentId::new(PeerId::random());
            
            assert!(pool.get(&peer_id).is_none());
        });
    }

    #[test]
    fn test_get_all_connected_empty() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let pool = ConnectionPool::new(config).await.unwrap();
            
            let connected = pool.get_all_connected();
            assert!(connected.is_empty());
        });
    }

    #[test]
    fn test_connection_count_empty() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let pool = ConnectionPool::new(config).await.unwrap();
            
            assert_eq!(pool.connection_count(), 0);
        });
    }

    #[test]
    fn test_disconnect_nonexistent() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let pool = ConnectionPool::new(config).await.unwrap();
            let peer_id = AgentId::new(PeerId::random());
            
            // Should not error when disconnecting non-existent peer
            pool.disconnect(&peer_id).await.unwrap();
        });
    }

    #[test]
    fn test_get_connection_stats_nonexistent() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let pool = ConnectionPool::new(config).await.unwrap();
            let peer_id = AgentId::new(PeerId::random());
            
            assert!(pool.get_connection_stats(&peer_id).is_none());
        });
    }

    #[test]
    fn test_resolve_agent_address() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let pool = ConnectionPool::new(config).await.unwrap();
            let agent = AgentInfo::new(
                AgentId::new(PeerId::random()),
                "test".to_string(),
                vec![],
                "model".to_string(),
            );
            
            // Default implementation returns None
            assert!(pool.resolve_agent_address(&agent).is_none());
        });
    }

    // ============================================
    // Key Management Tests
    // ============================================

    #[test]
    fn test_with_identity_key() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let pool = ConnectionPool::new(config).await.unwrap();
            
            let identity_key = IdentityKeyPair::generate();
            let pool = pool.with_identity_key(identity_key);
            
            assert!(pool.identity_key.is_some());
        });
    }

    #[test]
    fn test_with_signed_prekey() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let pool = ConnectionPool::new(config).await.unwrap();
            
            let identity_key = IdentityKeyPair::generate();
            let signed_prekey = SignedPreKey::generate(&identity_key, 1);
            let pool = pool.with_signed_prekey(signed_prekey);
            
            assert!(pool.signed_prekey.is_some());
        });
    }

    #[test]
    fn test_with_one_time_prekeys() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let pool = ConnectionPool::new(config).await.unwrap();
            
            let prekeys: Vec<_> = (0..50).map(|i| OneTimePreKey::generate(i)).collect();
            let pool = pool.with_one_time_prekeys(prekeys);
            
            assert_eq!(pool.one_time_prekeys.read().len(), 50);
        });
    }

    #[test]
    fn test_prekey_bundle_generation() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let mut pool = ConnectionPool::new(config).await.unwrap();
            pool.generate_identity_keys();
            
            // Generate multiple bundles
            let mut bundles = Vec::new();
            for _ in 0..10 {
                if let Some(bundle) = pool.get_prekey_bundle() {
                    bundles.push(bundle);
                }
            }
            
            assert_eq!(bundles.len(), 10);
            assert_eq!(pool.one_time_prekeys.read().len(), 90);
            
            // Verify each bundle has required fields
            for bundle in bundles {
                // Identity key should be 32 bytes
                assert_eq!(bundle.identity_key.len(), 32);
            }
        });
    }

    // ============================================
    // Error Handling Tests
    // ============================================

    #[test]
    fn test_encrypt_without_session() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let mut pool = ConnectionPool::new(config).await.unwrap();
            let peer_id = AgentId::new(PeerId::random());
            
            let result = pool.encrypt_message(&peer_id, b"test");
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(err_msg.contains("No session") || err_msg.contains("Failed to create session"));
        });
    }

    #[test]
    fn test_decrypt_without_session() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let mut pool = ConnectionPool::new(config).await.unwrap();
            let peer_id = AgentId::new(PeerId::random());
            
            let dummy_message = SessionMessage {
                session_id: "test".to_string(),
                message_type: vigilnet_crypto::MessageType::RatchetMessage(
                    vigilnet_crypto::EncryptedMessage {
                        header: vigilnet_crypto::MessageHeader {
                            previous_chain_length: 0,
                            message_number: 0,
                            public_key: None,
                        },
                        ciphertext: vec![1, 2, 3],
                    }
                ),
                payload: vec![1, 2, 3],
            };
            
            let result = pool.decrypt_message(&peer_id, &dummy_message);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(err_msg.contains("No session"));
        });
    }

    #[test]
    fn test_process_prekey_without_keys() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let mut pool = ConnectionPool::new(config).await.unwrap();
            let peer_id = AgentId::new(PeerId::random());
            
            let dummy_message = SessionMessage {
                session_id: "test".to_string(),
                message_type: vigilnet_crypto::MessageType::X3DHPreKey {
                    identity_key: [0u8; 32],
                    ephemeral_key: [0u8; 32],
                    spk_id: 1,
                    otpk_id: None,
                },
                payload: vec![1, 2, 3],
            };
            
            let result = pool.process_prekey_message(&peer_id, &dummy_message);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(err_msg.contains("Identity key not configured") || err_msg.contains("Signed prekey not configured"));
        });
    }

    #[test]
    fn test_process_non_prekey_message() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let mut pool = ConnectionPool::new(config).await.unwrap();
            pool.generate_identity_keys();
            let peer_id = AgentId::new(PeerId::random());
            
            let dummy_message = SessionMessage {
                session_id: "test".to_string(),
                message_type: vigilnet_crypto::MessageType::RatchetMessage(
                    vigilnet_crypto::EncryptedMessage {
                        header: vigilnet_crypto::MessageHeader {
                            previous_chain_length: 0,
                            message_number: 0,
                            public_key: None,
                        },
                        ciphertext: vec![1, 2, 3],
                    }
                ),
                payload: vec![1, 2, 3],
            };
            
            let result = pool.process_prekey_message(&peer_id, &dummy_message);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("Not a prekey message"));
        });
    }

    #[test]
    fn test_measure_latency_not_connected() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let pool = ConnectionPool::new(config).await.unwrap();
            let peer_id = AgentId::new(PeerId::random());
            
            let result = pool.measure_latency(&peer_id).await;
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("Not connected"));
        });
    }

    // ============================================
    // Edge Case Tests
    // ============================================

    #[test]
    fn test_empty_prekey_list() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let pool = ConnectionPool::new(config).await.unwrap();
            
            let identity_key = IdentityKeyPair::generate();
            let signed_prekey = SignedPreKey::generate(&identity_key, 1);
            
            let pool = pool
                .with_identity_key(identity_key)
                .with_signed_prekey(signed_prekey);
            
            // Empty prekey list - should still return bundle without one-time prekey
            let bundle = pool.get_prekey_bundle();
            assert!(bundle.is_some());
            assert!(bundle.unwrap().one_time_prekey.is_none());
        });
    }

    #[test]
    fn test_many_connections() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let pool = ConnectionPool::new(config).await.unwrap();
            
            // Test that pool can handle many connection attempts
            for i in 0..100 {
                let peer_id = AgentId::new(PeerId::random());
                // Just verify the pool structure works
                assert!(!pool.is_connected(&peer_id));
            }
        });
    }

    #[test]
    fn test_config_extreme_values() {
        let config = ConnectionPoolConfig {
            max_connections: usize::MAX,
            connection_timeout: Duration::from_secs(u64::MAX),
            idle_timeout: Duration::ZERO,
            keep_alive_interval: Duration::from_nanos(1),
            max_idle_timeout: Duration::from_secs(1),
            connect_timeout: Duration::from_millis(1),
            warmup_connections: 0,
        };
        
        assert_eq!(config.max_connections, usize::MAX);
        assert_eq!(config.idle_timeout, Duration::ZERO);
    }

    #[test]
    fn test_connection_state_transitions() {
        let peer_id = AgentId::new(PeerId::random());
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        
        let mut meta = ConnectionMeta::new(peer_id, addr);
        assert!(matches!(meta.state, ConnectionState::Connecting));
        
        meta.state = ConnectionState::Connected;
        assert!(matches!(meta.state, ConnectionState::Connected));
        
        meta.state = ConnectionState::Disconnected;
        assert!(matches!(meta.state, ConnectionState::Disconnected));
        
        meta.state = ConnectionState::Failed("test".to_string());
        assert!(matches!(meta.state, ConnectionState::Failed(_)));
    }

    #[test]
    fn test_latency_update() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let pool = ConnectionPool::new(config).await.unwrap();
            let peer_id = AgentId::new(PeerId::random());
            let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
            
            // Note: We can't actually connect, but we can verify the stats mechanism
            // by checking that we get None for non-existent connections
            assert!(pool.get_connection_stats(&peer_id).is_none());
        });
    }

    #[test]
    fn test_warmup_with_no_agents() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let pool = ConnectionPool::new(config).await.unwrap();
            
            let agents: Vec<AgentInfo> = vec![];
            let result = pool.warmup_connections(&agents).await;
            assert!(result.is_ok());
        });
    }

    #[test]
    fn test_warmup_with_agents() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let pool = ConnectionPool::new(config).await.unwrap();
            
            let agents: Vec<AgentInfo> = (0..10).map(|i| {
                AgentInfo::new(
                    AgentId::new(PeerId::random()),
                    format!("agent-{}", i),
                    vec![],
                    "model".to_string(),
                )
            }).collect();
            
            // Should complete without error even though agents don't have addresses
            let result = pool.warmup_connections(&agents).await;
            assert!(result.is_ok());
        });
    }

    #[test]
    fn test_concurrent_session_access() {
        use std::thread;
        
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let pool = Arc::new(ConnectionPool::new(config).await.unwrap());
            
            let mut handles = vec![];
            
            for i in 0..10 {
                let pool_clone = Arc::clone(&pool);
                let peer_id = AgentId::new(PeerId::random());
                
                let handle = thread::spawn(move || {
                    // These operations should be thread-safe
                    pool_clone.has_session(&peer_id);
                    pool_clone.session_count();
                    pool_clone.get_all_sessions();
                });
                
                handles.push(handle);
            }
            
            for handle in handles {
                handle.join().unwrap();
            }
        });
    }

    #[test]
    fn test_pool_result_type() {
        fn success_op() -> PoolResult<i32> {
            Ok(42)
        }
        
        fn fail_op() -> PoolResult<i32> {
            Err(ConnectionPoolError::ConnectionFailed("test".to_string()))
        }
        
        assert!(success_op().is_ok());
        assert!(fail_op().is_err());
        assert_eq!(success_op().unwrap(), 42);
    }

    #[test]
    fn test_connection_meta_timing() {
        let peer_id = AgentId::new(PeerId::random());
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        
        let before = Instant::now();
        let meta = ConnectionMeta::new(peer_id, addr);
        let after = Instant::now();
        
        assert!(meta.created_at >= before);
        assert!(meta.created_at <= after);
        assert!(meta.last_active >= before);
        assert!(meta.last_active <= after);
    }

    #[test]
    fn test_multiple_prekey_bundle_extractions() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let mut pool = ConnectionPool::new(config).await.unwrap();
            pool.generate_identity_keys();
            
            // Extract all prekeys
            let initial_count = pool.one_time_prekeys.read().len();
            let mut extracted = 0;
            
            for _ in 0..initial_count + 10 {
                if pool.get_prekey_bundle().is_some() {
                    extracted += 1;
                } else {
                    break;
                }
            }
            
            assert_eq!(extracted, initial_count);
            assert!(pool.get_prekey_bundle().is_none() || pool.one_time_prekeys.read().is_empty());
        });
    }

    #[test]
    fn test_transport_config_creation() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let result = ConnectionPool::create_transport_config(&config);
            assert!(result.is_ok());
        });
    }

    #[test]
    fn test_client_config_creation() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ConnectionPoolConfig::default();
            let pool = ConnectionPool::new(config).await.unwrap();
            let client_config = pool.create_client_config();
            assert!(client_config.is_ok());
        });
    }
}
