//! Error types for VigilNet core

use thiserror::Error;

/// Result type alias for VigilNet operations
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for VigilNet core
#[derive(Error, Debug)]
pub enum Error {
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// TOML parsing error
    #[error("TOML error: {0}")]
    Toml(#[from] toml::de::Error),

    /// TOML serialization error
    #[error("TOML serialization error: {0}")]
    TomlSer(#[from] toml::ser::Error),

    /// Crypto error
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// Network error
    #[error("Network error: {0}")]
    Network(String),

    /// Routing error
    #[error("Routing error: {0}")]
    Routing(String),

    /// Agent error
    #[error("Agent error: {0}")]
    Agent(String),

    /// Node not running
    #[error("Node is not running")]
    NotRunning,

    /// Node already running
    #[error("Node is already running")]
    AlreadyRunning,

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Circuit error
    #[error("Circuit error: {0}")]
    Circuit(String),

    /// E2EE error
    #[error("E2EE error: {0}")]
    E2EE(String),
}
