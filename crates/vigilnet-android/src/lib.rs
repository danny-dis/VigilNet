//! VigilNet Android
//!
//! Platform integration crate for Android mobile application.
//! Provides FFI bindings, VPN service integration, and multi-network management.

pub mod network_manager;
pub mod vpn_service;
pub mod battery;
pub mod ffi;

pub use network_manager::{NetworkBackend, NetworkManager, NetworkStatus};
pub use vpn_service::VpnTunnel;

/// Android platform error types
#[derive(Debug, thiserror::Error)]
pub enum AndroidError {
    #[error("VPN service error: {0}")]
    VpnError(String),

    #[error("Network backend error: {0}")]
    NetworkError(String),

    #[error("FFI error: {0}")]
    FfiError(String),

    #[error("Core error: {0}")]
    CoreError(#[from] vigilnet_core::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Result type for Android operations
pub type Result<T> = std::result::Result<T, AndroidError>;
