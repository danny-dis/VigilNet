//! VigilNet I2P
//!
//! I2P network integration via the SAM 3.1 protocol or embedded emissary router.
//! Provides garlic routing, tunnel management, and eepsite access.

pub mod sam;
pub mod tunnel;
pub mod naming;

/// I2P-specific error types
#[derive(Debug, thiserror::Error)]
pub enum I2pError {
    #[error("SAM bridge connection failed: {0}")]
    SamConnectionFailed(String),

    #[error("Tunnel creation failed: {0}")]
    TunnelFailed(String),

    #[error("I2P destination not found: {0}")]
    DestinationNotFound(String),

    #[error("Naming service error: {0}")]
    NamingError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for I2P operations
pub type Result<T> = std::result::Result<T, I2pError>;
