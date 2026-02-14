use serde::{Deserialize, Serialize};

/// WireGuard Interface Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardConfig {
    /// Private Key (base64)
    pub private_key: String,
    /// Listen Port (default: random)
    pub listen_port: Option<u16>,
    /// Address (CIDR)
    pub address: Vec<String>,
    /// DNS Servers
    pub dns: Vec<String>,
    /// MTU (default: 1420)
    pub mtu: Option<u16>,
    /// Peers
    pub peers: Vec<PeerConfig>,
}

/// WireGuard Peer Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    /// Public Key (base64)
    pub public_key: String,
    /// Preshared Key (base64, optional)
    pub preshared_key: Option<String>,
    /// Endpoint (host:port, optional)
    pub endpoint: Option<String>,
    /// Allowed IPs (CIDR)
    pub allowed_ips: Vec<String>,
    /// Persistent Keepalive (seconds, optional)
    pub persistent_keepalive: Option<u16>,
}

impl Default for WireGuardConfig {
    fn default() -> Self {
        Self {
            private_key: String::new(),
            listen_port: None,
            address: Vec::new(),
            dns: Vec::new(),
            mtu: Some(1420),
            peers: Vec::new(),
        }
    }
}
