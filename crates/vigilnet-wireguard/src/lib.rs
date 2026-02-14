//! VigilNet WireGuard
//!
//! WireGuard tunnel integration via boringtun (userspace implementation).
//! Provides fast encrypted tunnels between nodes or as VPN exit.

pub mod tunnel;
pub mod config;

/// WireGuard-specific error types
#[derive(Debug, thiserror::Error)]
pub enum WgError {
    #[error("Tunnel creation failed: {0}")]
    TunnelFailed(String),

    #[error("Peer configuration error: {0}")]
    PeerError(String),

    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for WireGuard operations
pub type Result<T> = std::result::Result<T, WgError>;
