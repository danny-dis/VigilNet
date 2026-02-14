//! VigilNet Tor
//!
//! Tor network integration via the Arti library.
//! Provides onion routing through the Tor network as an alternative
//! transport backend for VigilNet.

pub mod client;
pub mod bridge;
pub mod onion_service;

/// Tor-specific error types
#[derive(Debug, thiserror::Error)]
pub enum TorError {
    #[error("Tor client not initialized")]
    NotInitialized,

    #[error("Tor bootstrap failed: {0}")]
    BootstrapFailed(String),

    #[error("Tor circuit creation failed: {0}")]
    CircuitFailed(String),

    #[error("Bridge configuration error: {0}")]
    BridgeError(String),

    #[error("Onion service error: {0}")]
    OnionServiceError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for Tor operations
pub type Result<T> = std::result::Result<T, TorError>;
