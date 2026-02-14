//! VigilNet Nym
//!
//! Nym mixnet integration for metadata-resistant communication.
//! Provides 5-hop mixnet routing with cover traffic and Sphinx packets.

pub mod client;
pub mod mixnet;

/// Nym-specific error types
#[derive(Debug, thiserror::Error)]
pub enum NymError {
    #[error("Nym client not connected: {0}")]
    NotConnected(String),

    #[error("Mixnet routing failed: {0}")]
    RoutingFailed(String),

    #[error("Gateway error: {0}")]
    GatewayError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for Nym operations
pub type Result<T> = std::result::Result<T, NymError>;
