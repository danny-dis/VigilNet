//! VigilNet Core
//!
//! Main orchestration crate for the VigilNet privacy network.
//! Handles node lifecycle, configuration, and coordinates all subsystems.

pub mod config;
pub mod error;
pub mod node;
pub mod swarm;

pub use config::Config;
pub use error::{Error, Result};
pub use node::Node;
pub use swarm::{SwarmCommand, SwarmNotification, VigilNetSwarm};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
