//! VigilNet Agent Mesh
//!
//! Offline mesh fallback system for VigilNet agents providing resilient network communication.
//! Supports automatic fallback between QUIC, TCP, BLE, and Meshtastic networks.
//!
//! ## Features
//!
//! - **Network Fallback**: Automatic detection and fallback between network types
//! - **BLE Mesh**: Bluetooth Low Energy agent discovery and communication
//! - **Meshtastic Bridge**: Integration with Meshtastic MQTT protocol
//! - **DTN Store**: Delay-tolerant networking message persistence
//!
//! ## Usage
//!
//! ```rust
//! use vigilnet_agent_mesh::{MeshFallback, MeshFallbackConfig, NetworkType};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = MeshFallbackConfig::default();
//!     let mesh = MeshFallback::new(config)?;
//!     
//!     // Run the mesh fallback system
//!     mesh.run().await?;
//!     
//!     Ok(())
//! }
//! ```

pub mod ble_mesh;
pub mod dtn_store;
pub mod meshtastic_bridge;
pub mod mesh_fallback;

pub use ble_mesh::{BleConfig, BleDiscovery, BleMesh, BleMeshMessage, BlePeer};
pub use dtn_store::{DtnMessage, DtnMessageStatus, DtnMetadata, DtnStore, DtnStoreConfig};
pub use mesh_fallback::{
    ConnectionState, FallbackEvent, MeshCommand, MeshError, MeshFallback, MeshFallbackConfig,
    MeshMessage, MeshResult, NetworkStatus, NetworkType,
};
pub use meshtastic_bridge::{
    MeshtasticBridge, MeshtasticConfig, MeshtasticDeviceInfo, MeshtasticMessage,
    MeshtasticPosition, MeshtasticRouter, MeshtasticUser,
};

use anyhow::Result as AnyhowResult;
use tracing::info;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        let _config = MeshFallbackConfig::default();
        let _network_type = NetworkType::Quic;
        let _connection_state = ConnectionState::Connected;
        
        let _ble_config = BleConfig::default();
        let _meshtastic_config = MeshtasticConfig::default();
        let _dtn_config = DtnStoreConfig::default();
        
        let _dtn_message = DtnMessage::new(
            b"test".to_vec(),
            "dest".to_string(),
            "source".to_string(),
        );
    }

    #[tokio::test]
    async fn test_mesh_fallback_import() -> AnyhowResult<()> {
        let config = MeshFallbackConfig::default();
        let _mesh = MeshFallback::new(config)?;
        Ok(())
    }

    #[tokio::test]
    async fn test_ble_mesh_import() -> AnyhowResult<()> {
        let config = BleConfig::default();
        let _mesh = BleMesh::new(config)?;
        Ok(())
    }

    #[tokio::test]
    async fn test_meshtastic_bridge_import() -> AnyhowResult<()> {
        let config = MeshtasticConfig::default();
        let _bridge = MeshtasticBridge::new(config)?;
        Ok(())
    }
}
