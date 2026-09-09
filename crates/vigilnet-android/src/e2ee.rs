//! Mobile E2EE Transport
//!
//! Provides end-to-end encrypted transport for mobile agents.
//! Uses the agent-transport layer with mobile-optimized settings.

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};
use async_trait::async_trait;

use vigilnet_crypto::{PublicKey, SecretKey, KeyPair};
use vigilnet_agent_transport::{AgentTransport, AgentTransportConfig};

/// Mobile E2E transport configuration
#[derive(Debug, Clone)]
pub struct MobileE2eConfig {
    pub max_connections: usize,
    pub connection_timeout_secs: u64,
    pub idle_timeout_secs: u64,
    pub enable_udp: bool,
}

impl Default for MobileE2eConfig {
    fn default() -> Self {
        Self {
            max_connections: 10,
            connection_timeout_secs: 30,
            idle_timeout_secs: 300,
            enable_udp: true,
        }
    }
}

impl From<MobileE2eConfig> for AgentTransportConfig {
    fn from(cfg: MobileE2eConfig) -> Self {
        Self {
            max_connections: cfg.max_connections,
            connection_timeout: std::time::Duration::from_secs(cfg.connection_timeout_secs),
            idle_timeout: std::time::Duration::from_secs(cfg.idle_timeout_secs),
            enable_udp: cfg.enable_udp,
        }
    }
}

/// Mobile-optimized E2E transport for agents
pub struct MobileE2ETransport {
    config: MobileE2eConfig,
    keypair: Option<KeyPair>,
    transport: Option<vigilnet_agent_transport::AgentTransport>,
    peer_id: Option<libp2p::PeerId>,
}

impl MobileE2ETransport {
    /// Create a new mobile E2E transport
    pub fn new() -> Self {
        Self {
            config: MobileE2eConfig::default(),
            keypair: None,
            transport: None,
            peer_id: None,
        }
    }

    /// Create with custom config
    pub fn with_config(config: MobileE2eConfig) -> Self {
        Self {
            config,
            keypair: None,
            transport: None,
            peer_id: None,
        }
    }

    /// Initialize the transport (generate keys, setup)
    pub async fn initialize(&mut self) -> crate::Result<()> {
        info!("Initializing Mobile E2E Transport...");

        // Generate keypair for this mobile node
        let keypair = KeyPair::generate();
        let peer_id = libp2p::PeerId::from_public_key(
            libp2p::PublicKey::Ed25519(keypair.public().to_bytes().into())
        );

        info!("Generated peer ID: {}", peer_id);

        // Create transport
        let transport_config: AgentTransportConfig = self.config.clone().into();
        let transport = AgentTransport::new(transport_config, keypair.clone())
            .map_err(|e| crate::AndroidError::CoreError(
                vigilnet_core::Error::Other(format!("Transport init failed: {}", e))
            ))?;

        self.keypair = Some(keypair);
        self.transport = Some(transport);
        self.peer_id = Some(peer_id);

        info!("Mobile E2E Transport initialized");
        Ok(())
    }

    /// Get the peer ID
    pub fn peer_id(&self) -> Option<libp2p::PeerId> {
        self.peer_id
    }

    /// Get the public key
    pub fn public_key(&self) -> Option<&PublicKey> {
        self.keypair.as_ref().map(|kp| kp.public())
    }

    /// Get secret key for signing (circles, etc.)
    pub fn secret_key(&self) -> Option<&SecretKey> {
        self.keypair.as_ref().map(|kp| kp.secret())
    }

    /// Connect to a peer
    pub async fn connect(&mut self, peer_id: libp2p::PeerId, addr: libp2p::Multiaddr) 
        -> crate::Result<()> {
        let transport = self.transport.as_mut().ok_or(
            crate::AndroidError::CoreError(vigilnet_core::Error::Other(
                "Transport not initialized".to_string()
            ))
        )?;

        transport.connect(peer_id, addr).await
            .map_err(|e| crate::AndroidError::CoreError(
                vigilnet_core::Error::Other(format!("Connect failed: {}", e))
            ))
    }

    /// Send a message to a peer
    pub async fn send(&mut self, peer_id: libp2p::PeerId, data: Vec<u8>) -> crate::Result<()> {
        let transport = self.transport.as_mut().ok_or(
            crate::AndroidError::CoreError(vigilnet_core::Error::Other(
                "Transport not initialized".to_string()
            ))
        )?;

        transport.send(peer_id, data).await
            .map_err(|e| crate::AndroidError::CoreError(
                vigilnet_core::Error::Other(format!("Send failed: {}", e))
            ))
    }

    /// Get the underlying transport
    pub fn transport(&self) -> Option<&vigilnet_agent_transport::AgentTransport> {
        self.transport.as_ref()
    }
}

impl Default for MobileE2ETransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl vigilnet_agent_transport::TransportEndpoint for MobileE2ETransport {
    async fn send_encrypted(&mut self, recipient: &libp2p::PeerId, plaintext: &[u8]) 
        -> Result<(), vigilnet_agent_transport::TransportError> {
        let transport = self.transport.as_mut().ok_or(
            vigilnet_agent_transport::TransportError::NotInitialized
        )?;
        
        // Use the agent transport's send method
        // The transport handles encryption internally
        transport.send(recipient.clone(), plaintext.to_vec()).await
            .map_err(|e| vigilnet_agent_transport::TransportError::SendError(e.to_string()))
    }

    async fn receive_encrypted(&mut self) 
        -> Result<(libp2p::PeerId, Vec<u8>), vigilnet_agent_transport::TransportError> {
        // For mobile, we'd typically use a channel-based approach
        // This is a placeholder - actual implementation depends on transport design
        Err(vigilnet_agent_transport::TransportError::NotInitialized)
    }

    fn peer_id(&self) -> libp2p::PeerId {
        self.peer_id.unwrap_or_else(|| libp2p::PeerId::random())
    }
}
