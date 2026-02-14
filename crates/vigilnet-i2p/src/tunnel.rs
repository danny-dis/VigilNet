//! I2P Tunnel Management
//!
//! Manages I2P inbound and outbound tunnels.

use serde::{Deserialize, Serialize};
use tracing::info;

/// Tunnel direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelDirection {
    Inbound,
    Outbound,
}

/// Tunnel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    /// Tunnel length (number of hops)
    pub length: u8,
    /// Tunnel quantity (number of parallel tunnels)
    pub quantity: u8,
    /// Backup tunnel quantity
    pub backup_quantity: u8,
    /// Direction
    pub direction: TunnelDirection,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            length: 3,
            quantity: 2,
            backup_quantity: 0,
            direction: TunnelDirection::Outbound,
        }
    }
}

/// I2P tunnel pool manager
pub struct TunnelPool {
    /// Inbound tunnel config
    inbound: TunnelConfig,
    /// Outbound tunnel config
    outbound: TunnelConfig,
    /// Active tunnel count
    active_tunnels: usize,
}

impl TunnelPool {
    /// Create with defaults
    pub fn new() -> Self {
        Self {
            inbound: TunnelConfig {
                direction: TunnelDirection::Inbound,
                ..Default::default()
            },
            outbound: TunnelConfig::default(),
            active_tunnels: 0,
        }
    }

    /// Configure tunnel parameters
    pub fn configure(&mut self, inbound: TunnelConfig, outbound: TunnelConfig) {
        self.inbound = inbound;
        self.outbound = outbound;
        info!("Tunnel pool configured: in={} hops x{}, out={} hops x{}",
            self.inbound.length, self.inbound.quantity,
            self.outbound.length, self.outbound.quantity
        );
    }

    /// Get active tunnel count
    pub fn active_count(&self) -> usize {
        self.active_tunnels
    }
}

impl Default for TunnelPool {
    fn default() -> Self {
        Self::new()
    }
}
