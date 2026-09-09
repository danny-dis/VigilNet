//! VigilNet Routing
//!
//! Circuit building, path selection, and relay logic.
//! Provides E2EE encryption for all circuit traffic using Signal Protocol.

use tracing::{debug, error, info, instrument, trace, warn};

pub mod circuit;
pub mod path;
pub mod relay;
pub mod builder;
pub mod protocol;
pub mod relay_state;
pub mod policy;
pub mod padding;
pub mod encrypted_circuit;

pub use circuit::{Circuit, CircuitState, PendingCircuit};
pub use path::{PathSelector, PathStrategy, RelayInfo};
pub use relay::Relay;
pub use builder::{CircuitBuilder, BuilderConfig};
pub use relay_state::{RelayCircuit, RelayState};
pub use encrypted_circuit::{EncryptedCircuit, EncryptedCircuitMessage};

/// Result type for routing operations
pub type Result<T> = std::result::Result<T, RoutingError>;

/// Routing error types
#[derive(Debug, thiserror::Error)]
pub enum RoutingError {
    #[error("Circuit error: {0}")]
    Circuit(String),

    #[error("No path available: {0}")]
    NoPath(String),

    #[error("Relay error: {0}")]
    Relay(String),

    #[error("Crypto error: {0}")]
    Crypto(#[from] vigilnet_crypto::CryptoError),
}
