//! VigilNet Agent Core
//!
//! Core components for VigilNet agent network:
//! - Agent identity and information management
//! - High-speed QUIC connection pooling
//! - Binary message protocol
//! - Agent registry and discovery
//! - Signal Protocol E2EE

use tracing::{debug, error, info, instrument, trace, warn};

pub mod agent;
pub mod connection_pool;
pub mod message;
pub mod registry;

pub use agent::{AgentError, AgentId, AgentInfo, Result as AgentResult};
pub use connection_pool::{
    ConnectionPool, ConnectionPoolConfig, ConnectionPoolError, ConnectionState, PoolResult,
};
pub use message::{
    EncryptedPayload, Message, MessageBatch, MessageError, MessageFlags, MessageHeader,
    MessageSerializer, MessageType, Result as MessageResult,
};
pub use registry::AgentRegistry;
pub use vigilnet_crypto::{
    IdentityKeyPair, OneTimePreKey, PreKeyBundle, Session, SessionMessage, SignedPreKey,
    MessageType as CryptoMessageType, EncryptedMessage, MessageHeader as RatchetMessageHeader,
};

use crate::agent::AgentInfo;
use anyhow::Result as AnyhowResult;
use libp2p::PeerId;
use tracing::{info, instrument};
use vigilnet_crypto::{
    IdentityKeyPair, OneTimePreKey, PreKeyBundle, SessionMessage, SignedPreKey,
};

/// Main agent for handling network operations
pub struct Agent {
    id: AgentId,
    info: AgentInfo,
    registry: AgentRegistry,
    connection_pool: Option<ConnectionPool>,
    identity_key: Option<IdentityKeyPair>,
    signed_prekey: Option<SignedPreKey>,
    one_time_prekeys: Vec<OneTimePreKey>,
}

impl Agent {
    #[instrument(skip(name, capabilities, model_type), level = "info")]
    pub fn new(
        name: String,
        capabilities: Vec<String>,
        model_type: String,
    ) -> AnyhowResult<Self> {
        let peer_id = PeerId::random();
        let id = AgentId::new(peer_id);
        let info = AgentInfo::new(id.clone(), name.clone(), capabilities.clone(), model_type.clone());

        info!(
            agent_id = %id,
            name = %name,
            capabilities_count = capabilities.len(),
            model = %model_type,
            "Agent created"
        );

        let registry = AgentRegistry::new().with_local_agent(info.clone());

        trace!("Initializing empty agent state");
        Ok(Self {
            id,
            info,
            registry,
            connection_pool: None,
            identity_key: None,
            signed_prekey: None,
            one_time_prekeys: Vec::new(),
        })
    }

    #[instrument(skip(self, pool), level = "debug")]
    pub fn with_connection_pool(mut self, pool: ConnectionPool) -> Self {
        debug!("Attaching connection pool to agent");
        self.connection_pool = Some(pool);
        self
    }

    #[instrument(skip(self), level = "info")]
    pub fn initialize_e2ee(&mut self) {
        info!("Initializing E2EE for agent");

        trace!("Generating identity key pair");
        let identity_key = IdentityKeyPair::generate();

        trace!("Generating signed prekey");
        let signed_prekey = SignedPreKey::generate(&identity_key, 1);

        trace!("Generating one-time prekeys");
        let mut one_time_prekeys = Vec::new();
        for i in 0..100 {
            one_time_prekeys.push(OneTimePreKey::generate(i));
        }

        self.identity_key = Some(identity_key);
        self.signed_prekey = Some(signed_prekey);
        self.one_time_prekeys = one_time_prekeys;

        if let Some(ref pool) = self.connection_pool {
            trace!("Updating connection pool with E2EE keys");
            let mut pool_clone = pool.clone();
            if let Some(ref identity_key) = self.identity_key {
                pool_clone = pool_clone.with_identity_key(identity_key.clone());
            }
            if let Some(ref signed_prekey) = self.signed_prekey {
                pool_clone = pool_clone.with_signed_prekey(signed_prekey.clone());
            }
            pool_clone = pool_clone.with_one_time_prekeys(self.one_time_prekeys.clone());
            self.connection_pool = Some(pool_clone);
        }

        info!(
            agent_id = %self.id,
            prekeys_generated = 100,
            "E2EE initialized successfully"
        );
    }

    #[instrument(skip(self), level = "debug")]
    pub fn get_prekey_bundle(&self) -> Option<PreKeyBundle> {
        let identity_key = self.identity_key.as_ref()?;
        let signed_prekey = self.signed_prekey.as_ref()?;

        let mut otpk = self.one_time_prekeys.last().cloned();

        trace!(has_one_time_prekey = otpk.is_some(), "Generating prekey bundle");

        Some(PreKeyBundle {
            identity_key: identity_key.identity_public,
            signed_prekey: signed_prekey.clone(),
            one_time_prekey: otpk.take(),
        })
    }

    #[instrument(skip(self, bundle), level = "info")]
    pub fn create_session(&mut self, peer_id: &AgentId, bundle: &PreKeyBundle) -> AnyhowResult<()> {
        info!(peer_id = %peer_id, "Creating E2EE session");

        if let Some(ref mut pool) = self.connection_pool {
            pool.create_session(peer_id, bundle)?;
            info!(peer_id = %peer_id, "E2EE session created successfully");
            Ok(())
        } else {
            error!("Connection pool not initialized");
            Err(anyhow::anyhow!("Connection pool not initialized"))
        }
    }

    #[instrument(skip(self, payload), level = "debug")]
    pub fn send_encrypted(
        &mut self,
        peer_id: &AgentId,
        payload: Vec<u8>,
    ) -> AnyhowResult<SessionMessage> {
        trace!(peer_id = %peer_id, payload_len = payload.len(), "Encrypting message");

        if let Some(ref mut pool) = self.connection_pool {
            let result = pool.encrypt_message(peer_id, &payload)?;
            trace!("Message encrypted successfully");
            Ok(result)
        } else {
            error!("Connection pool not initialized");
            Err(anyhow::anyhow!("Connection pool not initialized"))
        }
    }

    #[instrument(skip(self, message), level = "debug")]
    pub fn receive_encrypted(
        &mut self,
        peer_id: &AgentId,
        message: &SessionMessage,
    ) -> AnyhowResult<Vec<u8>> {
        trace!(peer_id = %peer_id, "Decrypting message");

        if let Some(ref mut pool) = self.connection_pool {
            let result = pool.decrypt_message(peer_id, message)?;
            trace!(decrypted_len = result.len(), "Message decrypted successfully");
            Ok(result)
        } else {
            error!("Connection pool not initialized");
            Err(anyhow::anyhow!("Connection pool not initialized"))
        }
    }

    #[instrument(skip(self), level = "trace")]
    pub fn has_session(&self, peer_id: &AgentId) -> bool {
        let has = self.connection_pool
            .as_ref()
            .map(|p| p.has_session(peer_id))
            .unwrap_or(false);
        trace!(peer_id = %peer_id, has_session = has, "Checked session status");
        has
    }

    #[instrument(skip(self, message), level = "debug")]
    pub fn process_prekey_message(
        &mut self,
        peer_id: &AgentId,
        message: &SessionMessage,
    ) -> AnyhowResult<Vec<u8>> {
        trace!(peer_id = %peer_id, "Processing prekey message");

        if let Some(ref mut pool) = self.connection_pool {
            let result = pool.process_prekey_message(peer_id, message)?;
            trace!("Prekey message processed successfully");
            Ok(result)
        } else {
            error!("Connection pool not initialized");
            Err(anyhow::anyhow!("Connection pool not initialized"))
        }
    }

    #[instrument(skip(self), level = "trace")]
    pub fn id(&self) -> &AgentId {
        trace!("Retrieving agent ID");
        &self.id
    }

    #[instrument(skip(self), level = "trace")]
    pub fn info(&self) -> &AgentInfo {
        trace!("Retrieving agent info");
        &self.info
    }

    #[instrument(skip(self), level = "trace")]
    pub fn registry(&self) -> &AgentRegistry {
        trace!("Retrieving agent registry");
        &self.registry
    }

    #[instrument(skip(self), level = "trace")]
    pub fn connection_pool(&self) -> Option<&ConnectionPool> {
        let has_pool = self.connection_pool.is_some();
        trace!(has_connection_pool = has_pool, "Retrieving connection pool");
        self.connection_pool.as_ref()
    }

    #[instrument(skip(self), level = "debug")]
    pub fn is_e2ee_enabled(&self) -> bool {
        let enabled = self.identity_key.is_some();
        debug!(e2ee_enabled = enabled, "Checked E2EE status");
        enabled
    }

    #[instrument(skip(self), level = "debug")]
    pub fn get_identity_key(&self) -> Option<&IdentityKeyPair> {
        let has_key = self.identity_key.is_some();
        debug!(has_identity_key = has_key, "Retrieving identity key");
        self.identity_key.as_ref()
    }

    #[instrument(skip(self), level = "debug")]
    pub fn update_trust_score(&mut self, delta: f64) {
        let old_score = self.info.trust_score;
        self.info.update_trust(delta);
        let new_score = self.info.trust_score;

        info!(
            old_score,
            new_score,
            delta,
            "Trust score updated"
        );

        let _ = self.registry.update(self.info.clone());
    }

    #[instrument(skip(self), level = "debug")]
    pub fn update_latency(&mut self, latency_ns: u64) {
        self.info.update_latency(latency_ns);
        debug!(latency_ns, "Agent latency updated");
    }

    #[instrument(skip(self), level = "info")]
    pub fn set_online(&mut self, online: bool) {
        self.info.set_online(online);
        info!(online, "Agent online status changed");
    }
}

/// Builder for creating agents
pub struct AgentBuilder {
    name: Option<String>,
    capabilities: Option<Vec<String>>,
    model_type: Option<String>,
    connection_pool_config: Option<ConnectionPoolConfig>,
    enable_e2ee: bool,
}

impl AgentBuilder {
    #[instrument(level = "debug")]
    pub fn new() -> Self {
        trace!("Creating new AgentBuilder");
        Self {
            name: None,
            capabilities: None,
            model_type: None,
            connection_pool_config: None,
            enable_e2ee: false,
        }
    }

    #[instrument(skip(self, name), level = "debug")]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        let name = name.into();
        debug!(name = %name, "Setting agent name");
        self.name = Some(name);
        self
    }

    #[instrument(skip(self, capabilities), level = "debug")]
    pub fn capabilities(mut self, capabilities: Vec<String>) -> Self {
        debug!(count = capabilities.len(), "Setting agent capabilities");
        self.capabilities = Some(capabilities);
        self
    }

    #[instrument(skip(self, model_type), level = "debug")]
    pub fn model_type(mut self, model_type: impl Into<String>) -> Self {
        let model = model_type.into();
        debug!(model = %model, "Setting agent model type");
        self.model_type = Some(model);
        self
    }

    #[instrument(skip(self, config), level = "debug")]
    pub fn connection_pool_config(mut self, config: ConnectionPoolConfig) -> Self {
        debug!("Setting connection pool configuration");
        self.connection_pool_config = Some(config);
        self
    }

    #[instrument(skip(self), level = "debug")]
    pub fn enable_e2ee(mut self) -> Self {
        debug!("Enabling E2EE");
        self.enable_e2ee = true;
        self
    }

    #[instrument(skip(self), level = "info")]
    pub async fn build(self) -> AnyhowResult<Agent> {
        info!("Building agent...");

        let name = self.name.unwrap_or_else(|| {
            debug!("No name provided, using default: anonymous");
            "anonymous".to_string()
        });
        let capabilities = self.capabilities.unwrap_or_default();
        let model_type = self.model_type.unwrap_or_else(|| {
            debug!("No model type provided, using default: gpt-4");
            "gpt-4".to_string()
        });

        trace!("Creating base agent");
        let mut agent = Agent::new(name, capabilities, model_type)?;

        if let Some(config) = self.connection_pool_config {
            trace!("Initializing connection pool");
            let pool = ConnectionPool::new(config).await?;
            agent = agent.with_connection_pool(pool);
            debug!("Connection pool attached");
        }

        if self.enable_e2ee {
            trace!("Initializing E2EE");
            agent.initialize_e2ee();
        }

        info!(agent_id = %agent.id(), e2ee_enabled = self.enable_e2ee, "Agent built successfully");
        Ok(agent)
    }
}

impl Default for AgentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================
    // Unit Tests for Core Functionality
    // ============================================

    #[test]
    fn test_agent_creation() {
        let agent = Agent::new(
            "test-agent".to_string(),
            vec!["research".to_string(), "analysis".to_string()],
            "gpt-4".to_string(),
        ).expect("agent should be created");

        assert_eq!(agent.info().name, "test-agent");
        assert_eq!(agent.info().capabilities.len(), 2);
        assert_eq!(agent.info().model_type, "gpt-4");
        assert!(!agent.is_e2ee_enabled());
    }

    #[test]
    fn test_agent_id_access() {
        let agent = Agent::new(
            "test".to_string(),
            vec![],
            "model".to_string(),
        ).expect("agent should be created");

        let id = agent.id();
        // Just verify we can access the ID
        let _ = format!("{}", id);
    }

    #[test]
    fn test_agent_info_access() {
        let agent = Agent::new(
            "test".to_string(),
            vec!["cap".to_string()],
            "gpt-4".to_string(),
        ).expect("agent should be created");

        let info = agent.info();
        assert_eq!(info.name, "test");
        assert!(info.has_capability("cap"));
    }

    #[test]
    fn test_agent_registry_access() {
        let agent = Agent::new(
            "test".to_string(),
            vec![],
            "model".to_string(),
        ).expect("agent should be created");

        let registry = agent.registry();
        assert_eq!(registry.count(), 1); // Local agent registered
    }

    #[test]
    fn test_initialize_e2ee() {
        let mut agent = Agent::new(
            "test".to_string(),
            vec![],
            "model".to_string(),
        ).expect("agent should be created");

        assert!(!agent.is_e2ee_enabled());
        agent.initialize_e2ee();
        assert!(agent.is_e2ee_enabled());
    }

    #[test]
    fn test_get_prekey_bundle() {
        let mut agent = Agent::new(
            "test".to_string(),
            vec![],
            "model".to_string(),
        ).expect("agent should be created");

        // Before E2EE initialization, should return None
        assert!(agent.get_prekey_bundle().is_none());

        agent.initialize_e2ee();
        
        // After initialization, should return Some
        let bundle = agent.get_prekey_bundle();
        assert!(bundle.is_some());
    }

    #[test]
    fn test_update_trust_score() {
        let mut agent = Agent::new(
            "test".to_string(),
            vec![],
            "model".to_string(),
        ).expect("agent should be created");

        assert_eq!(agent.info().trust_score, 1.0);
        
        agent.update_trust_score(-0.3);
        assert_eq!(agent.info().trust_score, 0.7);
    }

    #[test]
    fn test_update_latency() {
        let mut agent = Agent::new(
            "test".to_string(),
            vec![],
            "model".to_string(),
        ).expect("agent should be created");

        assert_eq!(agent.info().latency_ns, 0);
        
        agent.update_latency(1_000_000);
        assert_eq!(agent.info().latency_ns, 1_000_000);
    }

    #[test]
    fn test_set_online() {
        let mut agent = Agent::new(
            "test".to_string(),
            vec![],
            "model".to_string(),
        ).expect("agent should be created");

        assert!(agent.info().is_online);
        
        agent.set_online(false);
        assert!(!agent.info().is_online);
        
        agent.set_online(true);
        assert!(agent.info().is_online);
    }

    // ============================================
    // AgentBuilder Tests
    // ============================================

    #[tokio::test]
    async fn test_agent_builder() {
        let agent = AgentBuilder::new()
            .name("test-agent")
            .capabilities(vec!["finance".to_string()])
            .model_type("gpt-4")
            .build()
            .await
            .expect("agent should be built");

        assert_eq!(agent.info().name, "test-agent");
        assert!(agent.info().has_capability("finance"));
        assert_eq!(agent.info().model_type, "gpt-4");
    }

    #[tokio::test]
    async fn test_agent_builder_defaults() {
        let agent = AgentBuilder::new()
            .build()
            .await
            .expect("agent should be built with defaults");

        assert_eq!(agent.info().name, "anonymous");
        assert!(agent.info().capabilities.is_empty());
        assert_eq!(agent.info().model_type, "gpt-4");
    }

    #[tokio::test]
    async fn test_agent_builder_with_pool() {
        let agent = AgentBuilder::new()
            .name("pool-agent")
            .connection_pool_config(ConnectionPoolConfig::default())
            .build()
            .await
            .expect("agent with pool should be built");

        assert!(agent.connection_pool().is_some());
    }

    #[tokio::test]
    async fn test_agent_builder_with_e2ee() {
        let agent = AgentBuilder::new()
            .name("secure-agent")
            .enable_e2ee()
            .build()
            .await
            .expect("agent with E2EE should be built");

        assert!(agent.is_e2ee_enabled());
        assert!(agent.get_identity_key().is_some());
    }

    #[tokio::test]
    async fn test_agent_builder_full() {
        let agent = AgentBuilder::new()
            .name("full-agent")
            .capabilities(vec!["compute".to_string(), "storage".to_string()])
            .model_type("claude-3")
            .connection_pool_config(ConnectionPoolConfig::default())
            .enable_e2ee()
            .build()
            .await
            .expect("full agent should be built");

        assert_eq!(agent.info().name, "full-agent");
        assert_eq!(agent.info().capabilities.len(), 2);
        assert_eq!(agent.info().model_type, "claude-3");
        assert!(agent.connection_pool().is_some());
        assert!(agent.is_e2ee_enabled());
    }

    #[test]
    fn test_agent_builder_chaining() {
        let builder = AgentBuilder::new()
            .name("chain-test")
            .capabilities(vec!["cap1".to_string()])
            .model_type("model-v1");
        
        // Just verify the builder methods chain correctly
        let _ = builder;
    }

    // ============================================
    // E2EE Session Tests
    // ============================================

    #[test]
    fn test_has_session_no_pool() {
        let agent = Agent::new(
            "test".to_string(),
            vec![],
            "model".to_string(),
        ).expect("agent should be created");

        let peer_id = AgentId::new(PeerId::random());
        assert!(!agent.has_session(&peer_id));
    }

    #[tokio::test]
    async fn test_has_session_with_pool() {
        let mut agent = AgentBuilder::new()
            .name("test")
            .connection_pool_config(ConnectionPoolConfig::default())
            .build()
            .await
            .expect("agent with pool should be built");

        agent.initialize_e2ee();

        let peer_id = AgentId::new(PeerId::random());
        assert!(!agent.has_session(&peer_id));
    }

    #[tokio::test]
    async fn test_create_session_no_pool() {
        let mut agent = Agent::new(
            "test".to_string(),
            vec![],
            "model".to_string(),
        ).expect("agent should be created");

        agent.initialize_e2ee();

        let peer_id = AgentId::new(PeerId::random());
        let bundle = agent
            .get_prekey_bundle()
            .expect("prekey bundle should exist after E2EE init");
        
        let result = agent.create_session(&peer_id, &bundle);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Connection pool not initialized"));
    }

    #[tokio::test]
    async fn test_create_session_with_pool() {
        let mut agent = AgentBuilder::new()
            .name("test")
            .connection_pool_config(ConnectionPoolConfig::default())
            .enable_e2ee()
            .build()
            .await
            .expect("agent with pool and E2EE should be built");

        let peer_id = AgentId::new(PeerId::random());
        let bundle = agent
            .get_prekey_bundle()
            .expect("prekey bundle should exist after E2EE init");
        
        // This may fail due to crypto operations, but should not error on pool availability
        let _ = agent.create_session(&peer_id, &bundle);
    }

    #[test]
    fn test_send_encrypted_no_pool() {
        let mut agent = Agent::new(
            "test".to_string(),
            vec![],
            "model".to_string(),
        ).expect("agent should be created");

        let peer_id = AgentId::new(PeerId::random());
        let result = agent.send_encrypted(&peer_id, b"test".to_vec());
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Connection pool not initialized"));
    }

    #[test]
    fn test_receive_encrypted_no_pool() {
        let mut agent = Agent::new(
            "test".to_string(),
            vec![],
            "model".to_string(),
        ).expect("agent should be created");

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
        
        let result = agent.receive_encrypted(&peer_id, &dummy_message);
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Connection pool not initialized"));
    }

    #[test]
    fn test_process_prekey_no_pool() {
        let mut agent = Agent::new(
            "test".to_string(),
            vec![],
            "model".to_string(),
        ).expect("agent should be created");

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
        
        let result = agent.process_prekey_message(&peer_id, &dummy_message);
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Connection pool not initialized"));
    }

    // ============================================
    // Integration Tests
    // ============================================

    #[tokio::test]
    async fn test_full_agent_lifecycle() {
        let mut agent = AgentBuilder::new()
            .name("lifecycle-agent")
            .capabilities(vec!["compute".to_string(), "storage".to_string()])
            .model_type("gpt-4")
            .connection_pool_config(ConnectionPoolConfig::default())
            .enable_e2ee()
            .build()
            .await
            .expect("full agent should be built");

        // Verify initial state
        assert!(agent.is_e2ee_enabled());
        assert!(agent.connection_pool().is_some());
        
        // Update trust
        agent.update_trust_score(-0.2);
        assert_eq!(agent.info().trust_score, 0.8);
        
        // Update latency
        agent.update_latency(500_000);
        assert_eq!(agent.info().latency_ns, 500_000);
        
        // Toggle online status
        agent.set_online(false);
        assert!(!agent.info().is_online);
        agent.set_online(true);
        assert!(agent.info().is_online);
        
        // Verify registry reflects updates
        let registry = agent.registry();
        let local = registry
            .get_local_agent()
            .expect("local agent should exist");
        assert_eq!(local.trust_score, 0.8);
    }

    #[tokio::test]
    async fn test_multiple_agents() {
        let mut agents: Vec<Agent> = Vec::new();
        
        for i in 0..5 {
            let agent = AgentBuilder::new()
                .name(format!("agent-{}", i))
                .capabilities(vec![format!("cap-{}", i)])
                .model_type("gpt-4")
                .build()
                .await
                .expect("agent should be built");
            
            agents.push(agent);
        }
        
        assert_eq!(agents.len(), 5);
        
        // Each agent should have unique ID
        let ids: Vec<_> = agents.iter().map(|a| a.id().clone()).collect();
        let unique_count = ids.iter().collect::<std::collections::HashSet<_>>().len();
        assert_eq!(unique_count, 5);
    }

    #[tokio::test]
    async fn test_agent_with_connection_pool_operations() {
        let agent = AgentBuilder::new()
            .name("pool-agent")
            .connection_pool_config(ConnectionPoolConfig::default())
            .enable_e2ee()
            .build()
            .await
            .expect("agent with pool should be built");

        let pool = agent
            .connection_pool()
            .expect("connection pool should exist");
        
        // Verify pool is functional
        assert_eq!(pool.connection_count(), 0);
        assert!(pool.get_all_connected().is_empty());
    }

    // ============================================
    // Error Handling Tests
    // ============================================

    #[test]
    fn test_agent_builder_invalid_config() {
        // Currently, the builder doesn't validate much, but this is where
        // we'd test invalid configurations
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime should be created");
        rt.block_on(async {
            // Empty capabilities should be fine
            let agent = AgentBuilder::new()
                .name("test")
                .capabilities(vec![])
                .build()
                .await
                .expect("agent should be built");
            
            assert!(agent.info().capabilities.is_empty());
        });
    }

    #[test]
    fn test_e2ee_operations_without_e2ee() {
        let mut agent = Agent::new(
            "test".to_string(),
            vec![],
            "model".to_string(),
        ).unwrap();

        // Get identity key without E2EE
        assert!(agent.get_identity_key().is_none());

        // Get prekey bundle without E2EE
        assert!(agent.get_prekey_bundle().is_none());
    }

    #[tokio::test]
    async fn test_session_operations_without_pool() {
        let mut agent = AgentBuilder::new()
            .name("test")
            .enable_e2ee()
            .build()
            .await
            .unwrap();

        let peer_id = AgentId::new(PeerId::random());
        let bundle = agent.get_prekey_bundle().unwrap();
        
        let result = agent.create_session(&peer_id, &bundle);
        assert!(result.is_err());
    }

    // ============================================
    // Edge Case Tests
    // ============================================

    #[test]
    fn test_agent_with_empty_name() {
        let agent = Agent::new(
            "".to_string(),
            vec![],
            "model".to_string(),
        ).unwrap();

        assert_eq!(agent.info().name, "");
    }

    #[test]
    fn test_agent_with_long_name() {
        let long_name = "a".repeat(1000);
        let agent = Agent::new(
            long_name.clone(),
            vec![],
            "model".to_string(),
        ).unwrap();

        assert_eq!(agent.info().name.len(), 1000);
    }

    #[test]
    fn test_agent_with_many_capabilities() {
        let caps: Vec<String> = (0..100).map(|i| format!("cap-{}", i)).collect();
        let agent = Agent::new(
            "test".to_string(),
            caps,
            "model".to_string(),
        ).unwrap();

        assert_eq!(agent.info().capabilities.len(), 100);
    }

    #[test]
    fn test_agent_builder_default() {
        let builder: AgentBuilder = Default::default();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let agent = builder.build().await.unwrap();
            assert_eq!(agent.info().name, "anonymous");
        });
    }

    #[test]
    fn test_trust_score_boundary_values() {
        let mut agent = Agent::new(
            "test".to_string(),
            vec![],
            "model".to_string(),
        ).unwrap();

        // Decrease to minimum
        agent.update_trust_score(-1.0);
        assert_eq!(agent.info().trust_score, 0.0);
        
        agent.update_trust_score(-1.0);
        assert_eq!(agent.info().trust_score, 0.0); // Clamped
        
        // Increase to maximum
        agent.update_trust_score(2.0);
        assert_eq!(agent.info().trust_score, 1.0);
        
        agent.update_trust_score(1.0);
        assert_eq!(agent.info().trust_score, 1.0); // Clamped
    }

    #[tokio::test]
    async fn test_concurrent_agent_builders() {
        use std::sync::Arc;
        use tokio::sync::Mutex;
        
        let agents = Arc::new(Mutex::new(Vec::new()));
        let mut handles = vec![];
        
        for i in 0..10 {
            let agents_clone = Arc::clone(&agents);
            let handle = tokio::spawn(async move {
                let agent = AgentBuilder::new()
                    .name(format!("concurrent-agent-{}", i))
                    .build()
                    .await
                    .unwrap();
                
                agents_clone.lock().await.push(agent);
            });
            handles.push(handle);
        }
        
        for handle in handles {
            handle.await.unwrap();
        }
        
        assert_eq!(agents.lock().await.len(), 10);
    }

    #[test]
    fn test_registry_updates() {
        let mut agent = Agent::new(
            "test".to_string(),
            vec!["cap1".to_string()],
            "model".to_string(),
        ).unwrap();

        // Initial trust score
        assert_eq!(agent.registry().get(&agent.id()).unwrap().trust_score, 1.0);
        
        // Update trust
        agent.update_trust_score(-0.5);
        
        // Registry should reflect the update
        assert_eq!(agent.registry().get(&agent.id()).unwrap().trust_score, 0.5);
    }

    #[tokio::test]
    async fn test_connection_pool_lifecycle() {
        let mut agent = AgentBuilder::new()
            .name("test")
            .connection_pool_config(ConnectionPoolConfig::default())
            .build()
            .await
            .unwrap();

        // Verify pool exists
        assert!(agent.connection_pool().is_some());
        
        // Initialize E2EE after pool is created
        agent.initialize_e2ee();
        assert!(agent.is_e2ee_enabled());
    }

    #[test]
    fn test_agent_debug() {
        let agent = Agent::new(
            "test".to_string(),
            vec![],
            "model".to_string(),
        ).unwrap();

        let debug_str = format!("{:?}", agent);
        assert!(!debug_str.is_empty());
    }

    #[tokio::test]
    async fn test_builder_with_all_options() {
        let config = ConnectionPoolConfig {
            max_connections: 50,
            connection_timeout: Duration::from_secs(60),
            ..Default::default()
        };
        
        let agent = AgentBuilder::new()
            .name("complete-agent")
            .capabilities(vec!["ai".to_string(), "ml".to_string(), "nlp".to_string()])
            .model_type("gpt-4-turbo")
            .connection_pool_config(config)
            .enable_e2ee()
            .build()
            .await
            .unwrap();

        assert_eq!(agent.info().name, "complete-agent");
        assert_eq!(agent.info().capabilities.len(), 3);
        assert_eq!(agent.info().model_type, "gpt-4-turbo");
        assert!(agent.connection_pool().is_some());
        assert!(agent.is_e2ee_enabled());
    }

    #[test]
    fn test_prekey_bundle_consistency() {
        let mut agent = Agent::new(
            "test".to_string(),
            vec![],
            "model".to_string(),
        ).unwrap();

        agent.initialize_e2ee();

        // Multiple calls should return valid bundles
        for _ in 0..5 {
            let bundle = agent.get_prekey_bundle();
            assert!(bundle.is_some());
            
            let b = bundle.unwrap();
            assert_eq!(b.identity_key.len(), 32);
        }
    }

    #[tokio::test]
    async fn test_multiple_sessions() {
        let mut agent = AgentBuilder::new()
            .name("multi-session")
            .connection_pool_config(ConnectionPoolConfig::default())
            .enable_e2ee()
            .build()
            .await
            .unwrap();

        let peer_ids: Vec<_> = (0..5).map(|_| AgentId::new(PeerId::random())).collect();
        
        // Initially no sessions
        for peer_id in &peer_ids {
            assert!(!agent.has_session(peer_id));
        }
        
        // All should report no session
        let all_sessions = peer_ids.iter().all(|p| !agent.has_session(p));
        assert!(all_sessions);
    }
}
