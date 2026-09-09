//! Node configuration management
//!
//! Provides configuration structures for VigilNet nodes including
//! network settings, privacy options, and feature toggles.
//!
//! # Example
//!
//! ```rust
//! use vigilnet_core::Config;
//!
//! // Load from file
//! let config = Config::load(std::path::Path::new("~/.vigilnet/config.toml"))?;
//!
//! // Or use defaults
//! let config = Config::default();
//! ```

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Path selection strategy for circuit routing
///
/// Determines how relays are selected when building anonymous circuits.
/// Different strategies trade off between performance and anonymity.
///
/// # Variants
///
/// - `Random`: Maximum unpredictability, best anonymity
/// - `LowestLatency`: Fastest paths, better performance
/// - `Hybrid`: Balance between randomness and performance (default)
/// - `Trusted`: Prefer well-established, reputable relays
///
/// # Example
///
/// ```rust
/// use vigilnet_core::PathStrategy;
///
/// let strategy = PathStrategy::Hybrid;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PathStrategy {
    /// Random path selection - maximum unpredictability
    Random,
    /// Lowest latency path - best performance
    LowestLatency,
    /// Hybrid: combine latency and randomness (default)
    #[default]
    Hybrid,
    /// Prefer trusted peers - reliability focused
    Trusted,
}

/// Main configuration for a VigilNet node
///
/// This is the top-level configuration structure that contains all settings
/// for running a VigilNet node. It can be loaded from/saved to TOML files.
///
/// # Example
///
/// ```rust
/// use vigilnet_core::Config;
///
/// let config = Config::default();
///
/// // Customize settings
/// let config = Config {
///     privacy: PrivacyConfig {
///         circuit_hops: 5,
///         ..Default::default()
///     },
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Node identity configuration (keys, certificates)
    pub identity: IdentityConfig,

    /// Network configuration (listen addresses, discovery)
    pub network: NetworkConfig,

    /// Privacy configuration (circuits, routing)
    pub privacy: PrivacyConfig,

    /// TUN interface configuration (VPN mode)
    pub tun: TunConfig,

    /// Relay configuration (traffic forwarding)
    pub relay: RelayConfig,

    /// Agent network configuration (optional E2EE agent network)
    pub agent: AgentConfig,
}

/// Relay settings
///
/// Controls whether this node will relay traffic for other peers
/// in the network. Relaying helps the network but consumes bandwidth.
///
/// # Example
///
/// ```rust
/// use vigilnet_core::RelayConfig;
///
/// let relay = RelayConfig {
///     enabled: true,
///     smart_mode: true,  // Auto-enable on public IPs
///     bandwidth_limit: 1024 * 1024,  // 1 MB/s limit
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Enable relaying traffic for others
    ///
    /// When enabled, this node will forward encrypted traffic
    /// for other peers, helping to create anonymous circuits.
    pub enabled: bool,
    /// Smart mode: Auto-enable if public IP detected
    ///
    /// Automatically enables relaying when the node detects
    /// it has a publicly reachable IP address.
    pub smart_mode: bool,
    /// Bandwidth limit in bytes per second (0 = unlimited)
    ///
    /// Limits the amount of bandwidth used for relaying traffic.
    /// Set to 0 for no limit.
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
    pub path_strategy: PathStrategy,
}

/// DNS resolution mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// Agent network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Enable agent network integration
    pub enabled: bool,
    /// Agent name
    pub name: String,
    /// Agent capabilities
    pub capabilities: Vec<String>,
    /// Agent model type
    pub model_type: String,
    /// Enable E2EE for agent communication
    pub enable_e2ee: bool,
    /// Connection pool size
    pub pool_size: usize,
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
                path_strategy: PathStrategy::Hybrid,
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
            agent: AgentConfig {
                enabled: false,
                name: "vigilnet-node".to_string(),
                capabilities: vec!["proxy".to_string(), "relay".to_string()],
                model_type: "gpt-4".to_string(),
                enable_e2ee: true,
                pool_size: 32,
            },
        }
    }
}

impl Config {
    /// Load configuration from a TOML file
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the configuration file
    ///
    /// # Returns
    ///
    /// Result containing the parsed Config or an error
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be read
    /// - The TOML is invalid
    /// - Required fields are missing
    ///
    /// # Example
    ///
    /// ```rust
    /// use vigilnet_core::Config;
    /// use std::path::Path;
    ///
    /// let config = Config::load(Path::new("config.toml"))?;
    /// ```
    pub fn load(path: &std::path::Path) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Save configuration to a TOML file
    ///
    /// Writes the configuration as a pretty-printed TOML file.
    /// Creates parent directories if they don't exist.
    ///
    /// # Arguments
    ///
    /// * `path` - Path where to save the configuration
    ///
    /// # Returns
    ///
    /// Result indicating success or error
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The parent directory cannot be created
    /// - The file cannot be written
    ///
    /// # Example
    ///
    /// ```rust
    /// use vigilnet_core::Config;
    /// use std::path::Path;
    ///
    /// let config = Config::default();
    /// config.save(Path::new("config.toml"))?;
    /// ```
    pub fn save(&self, path: &std::path::Path) -> crate::Result<()> {
        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}
