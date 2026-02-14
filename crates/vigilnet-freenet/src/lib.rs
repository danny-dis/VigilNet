//! VigilNet Freenet
//!
//! Freenet / Hyphanet integration for decentralized content storage
//! and retrieval through the Freenet network.

pub mod node;
pub mod content;
pub mod contracts;

/// Freenet-specific error types
#[derive(Debug, thiserror::Error)]
pub enum FreenetError {
    #[error("Freenet node not running: {0}")]
    NodeNotRunning(String),

    #[error("Content not found: {0}")]
    ContentNotFound(String),

    #[error("Content insert failed: {0}")]
    InsertFailed(String),

    #[error("Contract error: {0}")]
    ContractError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for Freenet operations
pub type Result<T> = std::result::Result<T, FreenetError>;
