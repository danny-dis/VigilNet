//! Nym Mixnet Client
//!
//! Wraps the Nym SDK to provide mixnet connectivity
//! for metadata-resistant message delivery.

use tracing::{info, error};
use nym_sdk::mixnet::{MixnetClient, MixnetClientBuilder, StoragePaths};
use std::path::PathBuf;

/// Nym client state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NymState {
    /// Not connected
    Disconnected,
    /// Connecting to gateway
    Connecting,
    /// Connected to the mixnet
    Connected,
    /// Error
    Error,
}

/// Nym mixnet client
pub struct NymClient {
    /// Current state
    state: NymState,
    /// Our Nym address (recipient address)
    address: Option<String>,
    /// Nym SDK client
    sdk_client: Option<MixnetClient>,
    /// Whether cover traffic is enabled
    cover_traffic: bool,
}

impl NymClient {
    /// Create a new client
    pub fn new() -> Self {
        Self {
            state: NymState::Disconnected,
            address: None,
            sdk_client: None,
            cover_traffic: true,
        }
    }

    /// Enable or disable cover traffic
    pub fn with_cover_traffic(mut self, enabled: bool) -> Self {
        self.cover_traffic = enabled;
        self
    }

    /// Connect to the Nym mixnet
    pub async fn connect(&mut self) -> crate::Result<()> {
        self.state = NymState::Connecting;
        info!("Connecting to Nym mixnet...");

        // Note: In a real Android environment, we would need to provide persistent storage paths
        let client = MixnetClientBuilder::new_ephemeral()
            .build()
            .await
            .map_err(|e| crate::NymError::RoutingFailed(e.to_string()))?;

        let mut client = client.connect_to_mixnet()
            .await
            .map_err(|e| crate::NymError::GatewayError(e.to_string()))?;

        self.address = Some(client.nym_address().to_string());
        self.sdk_client = Some(client);
        self.state = NymState::Connected;
        
        info!("Connected to Nym mixnet. Address: {}", self.address.as_ref().unwrap());
        Ok(())
    }

    /// Send data anonymously through the mixnet
    pub async fn send(&self, recipient: &str, data: &[u8]) -> crate::Result<()> {
        if self.state != NymState::Connected || self.sdk_client.is_none() {
            return Err(crate::NymError::NotConnected("Not connected".into()));
        }

        let address = recipient.parse()
            .map_err(|e: nym_sdk::mixnet::NymAddressError| crate::NymError::RoutingFailed(e.to_string()))?;

        info!("Sending {} bytes via Nym mixnet to {}", data.len(), recipient);
        
        self.sdk_client.as_ref().unwrap()
            .send_plain_message(address, data)
            .await
            .map_err(|e| crate::NymError::RoutingFailed(e.to_string()))?;
            
        Ok(())
    }

    /// Receive data from the mixnet
    pub async fn wait_for_message(&mut self) -> crate::Result<(String, Vec<u8>)> {
        if self.state != NymState::Connected || self.sdk_client.is_none() {
            return Err(crate::NymError::NotConnected("Not connected".into()));
        }

        if let Some(mut msg) = self.sdk_client.as_mut().unwrap().wait_for_messages().await {
            if let Some(first) = msg.pop() {
                // Return sender (if available/anonymous) and data
                return Ok(("anonymous".to_string(), first.message));
            }
        }
        
        Err(crate::NymError::RoutingFailed("No message received".into()))
    }

    /// Get our Nym address
    pub fn address(&self) -> Option<&str> {
        self.address.as_deref()
    }

    /// Disconnect from the mixnet
    pub async fn disconnect(&mut self) {
        info!("Disconnecting from Nym mixnet");
        self.sdk_client = None;
        self.state = NymState::Disconnected;
        self.address = None;
    }
}

impl Default for NymClient {
    fn default() -> Self {
        Self::new()
    }
}
