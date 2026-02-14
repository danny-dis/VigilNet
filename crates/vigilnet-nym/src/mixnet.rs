//! Mixnet Configuration
//!
//! Types for Nym mixnet routing configuration:
//! mix nodes, gateways, and traffic patterns.

use serde::{Deserialize, Serialize};

/// Mix node in the mixnet topology
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixNode {
    /// Node identity key
    pub identity_key: String,
    /// Sphinx key for packet encryption
    pub sphinx_key: String,
    /// Node address
    pub host: String,
    /// Layer in the mixnet (1-3)
    pub layer: u8,
    /// Node version
    pub version: String,
}

/// Gateway node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gateway {
    /// Gateway identity
    pub identity_key: String,
    /// Sphinx key
    pub sphinx_key: String,
    /// Address for client connections
    pub clients_host: String,
    /// Address for mix node connections
    pub mix_host: String,
}

/// Mixnet topology
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixnetTopology {
    /// Mix nodes organized by layer
    pub mix_nodes: Vec<MixNode>,
    /// Available gateways
    pub gateways: Vec<Gateway>,
    /// Epoch number
    pub epoch: u64,
}

/// Cover traffic configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverTrafficConfig {
    /// Average delay between cover packets (ms)
    pub average_delay_ms: u64,
    /// Whether to send cover traffic
    pub enabled: bool,
    /// Maximum packet size
    pub packet_size: usize,
}

impl Default for CoverTrafficConfig {
    fn default() -> Self {
        Self {
            average_delay_ms: 200,
            enabled: true,
            packet_size: 2048, // standard Sphinx packet size
        }
    }
}
