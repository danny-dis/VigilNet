//! Node configuration management

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main configuration for a VigilNet node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Node identity configuration
    pub identity: IdentityConfig,

    /// Network configuration
    pub network: NetworkConfig,

    /// Privacy configuration
    pub privacy: PrivacyConfig,

    /// TUN interface configuration
    pub tun: TunConfig,

    /// Relay configuration
    pub relay: RelayConfig,
}

/// Relay settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Enable relaying traffic for others
    pub enabled: bool,
    /// Smart mode: Auto-enable if public IP detected
    pub smart_mode: bool,
    /// Bandwidth limit in bytes per second (0 = unlimited)
    pub bandwidth_limit: u64,
}

/// Identity and key configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Path to store identity keys
    pub key_path: PathBuf,

    /// Whether to generate new keys on first run
    pub auto_generate: bool,
}

/// Network settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Listen addresses for incoming connections
    pub listen_addrs: Vec<String>,

    /// Bootstrap peers (optional)
    pub bootstrap_peers: Vec<String>,

    /// Enable mDNS for local discovery
    pub enable_mdns: bool,

    /// Enable DHT for global discovery
    pub enable_dht: bool,
}

/// Privacy and routing settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    /// Number of hops in onion circuits (3-10)
    pub circuit_hops: u8,

    /// Whether to use garlic routing (bundle messages)
    pub garlic_routing: bool,

    /// DNS routing mode
    pub dns_mode: DnsMode,

    /// Path selection strategy
    pub path_strategy: vigilnet_routing::PathStrategy,
}

/// DNS resolution mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DnsMode {
    /// Use local system DNS
    Local,
    /// Route DNS through VigilNet
    Tunnel,
}

/// TUN interface settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunConfig {
    /// Whether to enable TUN interface
    pub enabled: bool,

    /// TUN device name
    pub device_name: String,

    /// MTU size
    pub mtu: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            identity: IdentityConfig {
                key_path: PathBuf::from("~/.vigilnet/keys"),
                auto_generate: true,
            },
            network: NetworkConfig {
                listen_addrs: vec!["/ip4/0.0.0.0/tcp/0".to_string()],
                bootstrap_peers: vec![],
                enable_mdns: true,
                enable_dht: true,
            },
            privacy: PrivacyConfig {
                circuit_hops: 3,
                garlic_routing: false,
                dns_mode: DnsMode::Local,
                path_strategy: vigilnet_routing::PathStrategy::Hybrid,
            },
            tun: TunConfig {
                enabled: false,
                device_name: "vigilnet0".to_string(),
                mtu: 1500,
            },
            relay: RelayConfig {
                enabled: false,
                smart_mode: true,
                bandwidth_limit: 0,
            },
        }
    }
}

impl Config {
    /// Load configuration from a TOML file
    pub fn load(path: &std::path::Path) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Save configuration to a TOML file
    pub fn save(&self, path: &std::path::Path) -> crate::Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}
