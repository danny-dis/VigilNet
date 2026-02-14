//! VigilNet TUN Interface
//!
//! Virtual network device for system-wide VPN functionality.

pub mod device;
pub mod packet;
pub mod firewall;
pub mod dhcp_guard;
pub mod namespace;

pub use device::{TunConfig, TunDevice};
pub use dhcp_guard::DhcpGuard;
pub use firewall::{Firewall, FirewallConfig};
pub use packet::IpPacket;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TunError {
    #[error("Device creation failed: {0}")]
    CreationFailed(String),

    #[error("Device not ready")]
    NotReady,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Permission denied - run as administrator/root")]
    PermissionDenied,

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Operation not supported on this platform")]
    NotSupported,

    #[error("Packet processing error: {0}")]
    PacketError(String),
}

pub type Result<T> = std::result::Result<T, TunError>;
