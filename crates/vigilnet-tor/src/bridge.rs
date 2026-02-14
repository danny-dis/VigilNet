//! Tor Bridge / Pluggable Transport Support
//!
//! Configures bridges and pluggable transports (obfs4, snowflake, meek)
//! for censorship circumvention.

use serde::{Deserialize, Serialize};
use tracing::info;

/// Pluggable transport type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportType {
    /// obfs4 (obfuscation layer 4)
    Obfs4,
    /// Snowflake (WebRTC-based)
    Snowflake,
    /// Meek (domain fronting via CDN)
    Meek,
    /// WebTunnel (HTTPS-based)
    WebTunnel,
}

/// Bridge configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Transport type
    pub transport: TransportType,
    /// Bridge address (ip:port)
    pub address: String,
    /// Bridge fingerprint
    pub fingerprint: Option<String>,
    /// Transport-specific parameters
    pub params: std::collections::HashMap<String, String>,
}

/// Bridge manager
pub struct BridgeManager {
    /// Configured bridges
    bridges: Vec<BridgeConfig>,
    /// Whether to auto-request bridges from BridgeDB / Moat
    auto_request: bool,
}

impl BridgeManager {
    /// Create a new bridge manager
    pub fn new() -> Self {
        Self {
            bridges: Vec::new(),
            auto_request: false,
        }
    }

    /// Add a bridge
    pub fn add_bridge(&mut self, bridge: BridgeConfig) {
        info!("Adding {:?} bridge: {}", bridge.transport, bridge.address);
        self.bridges.push(bridge);
    }

    /// Get all configured bridges
    pub fn bridges(&self) -> &[BridgeConfig] {
        &self.bridges
    }

    /// Enable auto-requesting bridges when direct Tor fails
    pub fn enable_auto_request(&mut self) {
        self.auto_request = true;
    }

    /// Request bridges from BridgeDB/Moat
    pub async fn request_bridges(&self, transport: TransportType) -> crate::Result<Vec<BridgeConfig>> {
        info!("Requesting {:?} bridges from BridgeDB", transport);
        // TODO: Implement Moat/BridgeDB CAPTCHA-based bridge request
        Ok(Vec::new())
    }

    /// Add default snowflake bridges
    pub fn add_default_snowflake(&mut self) {
        self.add_bridge(BridgeConfig {
            transport: TransportType::Snowflake,
            address: "192.0.2.3:1".to_string(),
            fingerprint: Some("2B280B23E1107BB62ABFC40DDCC8824814F80A72".to_string()),
            params: [
                ("url".to_string(), "https://snowflake-broker.torproject.net.global.prod.fastly.net/".to_string()),
                ("front".to_string(), "cdn.sstatic.net".to_string()),
            ].into(),
        });
    }
}

impl Default for BridgeManager {
    fn default() -> Self {
        Self::new()
    }
}
