//! WireGuard Tunnel (boringtun integration)
//!
//! Creates and manages WireGuard tunnels for fast,
//! encrypted point-to-point connectivity.

use tracing::{info, debug};

/// Tunnel state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    /// Not initialized
    Down,
    /// Handshake in progress
    Handshaking,
    /// Tunnel active
    Up,
    /// Error
    Error,
}

/// WireGuard tunnel statistics
#[derive(Debug, Clone, Default)]
pub struct TunnelStats {
    /// Bytes sent
    pub tx_bytes: u64,
    /// Bytes received
    pub rx_bytes: u64,
    /// Last handshake timestamp
    pub last_handshake: Option<u64>,
    /// Keepalive interval (seconds)
    pub keepalive_interval: u16,
}

/// WireGuard tunnel
pub struct WgTunnel {
    /// Current state
    state: TunnelState,
    /// Statistics
    stats: TunnelStats,
    /// Our private key
    private_key: Option<[u8; 32]>,
    /// Peer public key
    peer_public_key: Option<[u8; 32]>,
    /// Preshared key (optional)
    preshared_key: Option<[u8; 32]>,
    /// Endpoint (ip:port)
    endpoint: Option<String>,
    /// Allowed IPs (CIDR)
    allowed_ips: Vec<String>,
    /// Persistent keepalive (seconds, 0 = disabled)
    keepalive: u16,
    /// Listen port (0 = random)
    listen_port: u16,
}

impl WgTunnel {
    /// Create a new WireGuard tunnel
    pub fn new() -> Self {
        Self {
            state: TunnelState::Down,
            stats: TunnelStats::default(),
            private_key: None,
            peer_public_key: None,
            preshared_key: None,
            endpoint: None,
            allowed_ips: vec!["0.0.0.0/0".to_string()], // route all
            keepalive: 25,
            listen_port: 0,
        }
    }

    /// Set our private key
    pub fn with_private_key(mut self, key: [u8; 32]) -> Self {
        self.private_key = Some(key);
        self
    }

    /// Set peer's public key
    pub fn with_peer_key(mut self, key: [u8; 32]) -> Self {
        self.peer_public_key = Some(key);
        self
    }

    /// Set preshared key
    pub fn with_preshared_key(mut self, key: [u8; 32]) -> Self {
        self.preshared_key = Some(key);
        self
    }

    /// Set endpoint
    pub fn with_endpoint(mut self, endpoint: &str) -> Self {
        self.endpoint = Some(endpoint.to_string());
        self
    }

    /// Set allowed IPs
    pub fn with_allowed_ips(mut self, ips: Vec<String>) -> Self {
        self.allowed_ips = ips;
        self
    }

    /// Set keepalive interval
    pub fn with_keepalive(mut self, seconds: u16) -> Self {
        self.keepalive = seconds;
        self
    }

    /// Start the WireGuard tunnel
    pub async fn start(&mut self) -> crate::Result<()> {
        let private_key = self.private_key.ok_or_else(|| {
            crate::WgError::TunnelFailed("Private key not set".into())
        })?;
        let peer_key = self.peer_public_key.ok_or_else(|| {
            crate::WgError::PeerError("Peer public key not set".into())
        })?;

        info!("Starting WireGuard tunnel to {:?}", self.endpoint);
        self.state = TunnelState::Handshaking;

        // TODO: Create boringtun tunnel
        // let tunnel = boringtun::noise::Tunn::new(
        //     StaticSecret::from(private_key),
        //     PublicKey::from(peer_key),
        //     self.preshared_key.map(|k| k.into()),
        //     Some(self.keepalive),
        //     0, // tunnel index
        //     None, // rate limiter
        // ).map_err(|e| crate::WgError::TunnelFailed(e.to_string()))?;

        self.state = TunnelState::Up;
        info!("WireGuard tunnel established (stub)");
        Ok(())
    }

    /// Stop the tunnel
    pub async fn stop(&mut self) {
        info!("Stopping WireGuard tunnel");
        self.state = TunnelState::Down;
    }

    /// Process an incoming packet from the network
    pub fn decapsulate(&mut self, _packet: &[u8]) -> crate::Result<Vec<u8>> {
        // TODO: tunnel.decapsulate(None, packet, &mut dst_buf)
        Ok(Vec::new())
    }

    /// Encapsulate a packet for sending through the tunnel
    pub fn encapsulate(&mut self, _packet: &[u8]) -> crate::Result<Vec<u8>> {
        // TODO: tunnel.encapsulate(packet, &mut dst_buf)
        Ok(Vec::new())
    }

    /// Get current state
    pub fn state(&self) -> TunnelState {
        self.state
    }

    /// Get statistics
    pub fn stats(&self) -> &TunnelStats {
        &self.stats
    }
}

impl Default for WgTunnel {
    fn default() -> Self {
        Self::new()
    }
}
