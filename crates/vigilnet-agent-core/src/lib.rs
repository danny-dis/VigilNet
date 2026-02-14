//! VigilNet Agent Core
//!
//! Core components for VigilNet agent network:
//! - Agent identity and information management
//! - High-speed QUIC connection pooling
//! - Binary message protocol
//! - Agent registry and discovery
//! - Signal Protocol E2EE

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
    #[instrument(skip_all, name = "Agent::new")]
    pub fn new(
        name: String,
        capabilities: Vec<String>,
        model_type: String,
    ) -> AnyhowResult<Self> {
        let peer_id = PeerId::random();
        let id = AgentId::new(peer_id);
        let info = AgentInfo::new(id.clone(), name, capabilities, model_type);

        info!(
            peer_id = %id,
            name = %info.name,
            capabilities = ?info.capabilities,
            model = %info.model_type,
            "Agent initialized"
        );

        let registry = AgentRegistry::new().with_local_agent(info.clone());

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

    pub fn with_connection_pool(mut self, pool: ConnectionPool) -> Self {
        self.connection_pool = Some(pool);
        self
    }

    pub fn initialize_e2ee(&mut self) {
        let identity_key = IdentityKeyPair::generate();
        let signed_prekey = SignedPreKey::generate(&identity_key, 1);

        let mut one_time_prekeys = Vec::new();
        for i in 0..100 {
            one_time_prekeys.push(OneTimePreKey::generate(i));
        }

        self.identity_key = Some(identity_key);
        self.signed_prekey = Some(signed_prekey);
        self.one_time_prekeys = one_time_prekeys;

        if let Some(ref pool) = self.connection_pool {
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

        info!(agent_id = %self.id, "E2EE initialized");
    }

    pub fn get_prekey_bundle(&self) -> Option<PreKeyBundle> {
        let identity_key = self.identity_key.as_ref()?;
        let signed_prekey = self.signed_prekey.as_ref()?;

        let mut otpk = self.one_time_prekeys.last().cloned();

        Some(PreKeyBundle {
            identity_key: identity_key.identity_public,
            signed_prekey: signed_prekey.clone(),
            one_time_prekey: otpk.take(),
        })
    }

    pub fn create_session(&mut self, peer_id: &AgentId, bundle: &PreKeyBundle) -> AnyhowResult<()> {
        if let Some(ref mut pool) = self.connection_pool {
            pool.create_session(peer_id, bundle)?;
            info!(peer_id = %peer_id, "E2EE session created");
            Ok(())
        } else {
            Err(anyhow::anyhow!("Connection pool not initialized"))
        }
    }

    pub fn send_encrypted(
        &mut self,
        peer_id: &AgentId,
        payload: Vec<u8>,
    ) -> AnyhowResult<SessionMessage> {
        if let Some(ref mut pool) = self.connection_pool {
            pool.encrypt_message(peer_id, &payload)
        } else {
            Err(anyhow::anyhow!("Connection pool not initialized"))
        }
    }

    pub fn receive_encrypted(
        &mut self,
        peer_id: &AgentId,
        message: &SessionMessage,
    ) -> AnyhowResult<Vec<u8>> {
        if let Some(ref mut pool) = self.connection_pool {
            pool.decrypt_message(peer_id, message)
        } else {
            Err(anyhow::anyhow!("Connection pool not initialized"))
        }
    }

    pub fn has_session(&self, peer_id: &AgentId) -> bool {
        self.connection_pool
            .as_ref()
            .map(|p| p.has_session(peer_id))
            .unwrap_or(false)
    }

    pub fn process_prekey_message(
        &mut self,
        peer_id: &AgentId,
        message: &SessionMessage,
    ) -> AnyhowResult<Vec<u8>> {
        if let Some(ref mut pool) = self.connection_pool {
            pool.process_prekey_message(peer_id, message)
        } else {
            Err(anyhow::anyhow!("Connection pool not initialized"))
        }
    }

    pub fn id(&self) -> &AgentId {
        &self.id
    }

    pub fn info(&self) -> &AgentInfo {
        &self.info
    }

    pub fn registry(&self) -> &AgentRegistry {
        &self.registry
    }

    pub fn connection_pool(&self) -> Option<&ConnectionPool> {
        self.connection_pool.as_ref()
    }

    pub fn is_e2ee_enabled(&self) -> bool {
        self.identity_key.is_some()
    }

    pub fn get_identity_key(&self) -> Option<&IdentityKeyPair> {
        self.identity_key.as_ref()
    }

    pub fn update_trust_score(&mut self, delta: f64) {
        self.info.update_trust(delta);
        let _ = self.registry.update(self.info.clone());
    }

    pub fn update_latency(&mut self, latency_ns: u64) {
        self.info.update_latency(latency_ns);
    }

    pub fn set_online(&mut self, online: bool) {
        self.info.set_online(online);
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
    pub fn new() -> Self {
        Self {
            name: None,
            capabilities: None,
            model_type: None,
            connection_pool_config: None,
            enable_e2ee: false,
        }
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn capabilities(mut self, capabilities: Vec<String>) -> Self {
        self.capabilities = Some(capabilities);
        self
    }

    pub fn model_type(mut self, model_type: impl Into<String>) -> Self {
        self.model_type = Some(model_type.into());
        self
    }

    pub fn connection_pool_config(mut self, config: ConnectionPoolConfig) -> Self {
        self.connection_pool_config = Some(config);
        self
    }

    pub fn enable_e2ee(mut self) -> Self {
        self.enable_e2ee = true;
        self
    }

    pub async fn build(self) -> AnyhowResult<Agent> {
        let name = self.name.unwrap_or_else(|| "anonymous".to_string());
        let capabilities = self.capabilities.unwrap_or_default();
        let model_type = self.model_type.unwrap_or_else(|| "gpt-4".to_string());

        let mut agent = Agent::new(name, capabilities, model_type)?;

        if let Some(config) = self.connection_pool_config {
            let pool = ConnectionPool::new(config).await?;
            agent = agent.with_connection_pool(pool);
        }

        if self.enable_e2ee {
            agent.initialize_e2ee();
        }

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

    #[tokio::test]
    async fn test_agent_builder() -> AnyhowResult<()> {
        let agent = AgentBuilder::new()
            .name("test-agent")
            .capabilities(vec!["finance".to_string()])
            .model_type("gpt-4")
            .build()
            .await?;

        assert_eq!(agent.info().name, "test-agent");
        assert!(agent.info().has_capability("finance"));
        assert_eq!(agent.info().model_type, "gpt-4");

        Ok(())
    }
}
