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
#[cfg(test)]
use tracing::info;

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================
    // Unit Tests for Core Functionality
    // ============================================

    #[test]
    fn test_module_exports() {
        // Verify all expected types are exported
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

    #[test]
    fn test_network_type_variants() {
        // Test all network type variants exist
        let types = vec![
            NetworkType::Quic,
            NetworkType::Tcp,
            NetworkType::Ble,
            NetworkType::Meshtastic,
            NetworkType::Offline,
        ];
        
        for network_type in types {
            let priority = network_type.priority();
            assert!(priority <= 4);
        }
    }

    #[test]
    fn test_network_type_priorities() {
        // Test that priority ordering is correct
        assert!(NetworkType::Quic.priority() > NetworkType::Tcp.priority());
        assert!(NetworkType::Tcp.priority() > NetworkType::Ble.priority());
        assert!(NetworkType::Ble.priority() > NetworkType::Meshtastic.priority());
        assert!(NetworkType::Meshtastic.priority() > NetworkType::Offline.priority());
    }

    #[test]
    fn test_connection_state_variants() {
        // Test all connection state variants
        let states = vec![
            ConnectionState::Disconnected,
            ConnectionState::Connecting,
            ConnectionState::Connected,
            ConnectionState::Reconnecting,
        ];
        
        for state in states {
            // Just verify they can be created
            let _ = format!("{:?}", state);
        }
    }

    #[test]
    fn test_connection_state_default() {
        let state: ConnectionState = Default::default();
        assert!(matches!(state, ConnectionState::Disconnected));
    }

    #[test]
    fn test_network_status_default() {
        let status: NetworkStatus = Default::default();
        assert!(matches!(status.network_type, NetworkType::Offline));
        assert!(matches!(status.connection_state, ConnectionState::Disconnected));
        assert!(status.latency_ms.is_none());
        assert!(status.bandwidth_mbps.is_none());
        assert!(status.available_networks.is_empty());
    }

    #[test]
    fn test_mesh_fallback_config_default() {
        let config = MeshFallbackConfig::default();
        assert!(config.enable_ble == cfg!(target_os = "linux"));
        assert!(config.enable_meshtastic);
        assert!(config.quic_endpoints.is_empty());
        assert!(config.tcp_endpoints.is_empty());
    }

    #[test]
    fn test_ble_config_default() {
        let config = BleConfig::default();
        assert_eq!(config.device_name, "VigilNet-Agent");
        assert_eq!(config.max_connections, 5);
        assert_eq!(config.advertise_interval_ms, 160);
        assert_eq!(config.scan_duration_secs, 10);
    }

    #[test]
    fn test_meshtastic_config_default() {
        let config = MeshtasticConfig::default();
        assert_eq!(config.mqtt_broker, "mqtt.meshtastic.org");
        assert_eq!(config.mqtt_port, 1883);
        assert_eq!(config.root_topic, "msh");
    }

    #[test]
    fn test_dtn_store_config_default() {
        let config = DtnStoreConfig::default();
        assert_eq!(config.max_messages, 10000);
        assert_eq!(config.max_size_bytes, 100 * 1024 * 1024);
        assert_eq!(config.cleanup_interval_secs, 3600);
    }

    #[test]
    fn test_dtn_message_creation() {
        let message = DtnMessage::new(
            b"test payload".to_vec(),
            "destination".to_string(),
            "source".to_string(),
        );
        
        assert!(!message.id.is_empty());
        assert_eq!(message.status, DtnMessageStatus::Pending);
        assert!(!message.is_expired());
        assert_eq!(message.retry_count, 0);
    }

    #[test]
    fn test_dtn_message_with_priority() {
        let message = DtnMessage::new(
            b"test".to_vec(),
            "dest".to_string(),
            "source".to_string(),
        ).with_priority(5);
        
        assert_eq!(message.priority, 5);
    }

    #[test]
    fn test_dtn_message_with_ttl() {
        let message = DtnMessage::new(
            b"test".to_vec(),
            "dest".to_string(),
            "source".to_string(),
        ).with_ttl(3600);
        
        assert!(!message.is_expired());
    }

    #[test]
    fn test_dtn_message_increment_retry() {
        let mut message = DtnMessage::new(
            b"test".to_vec(),
            "dest".to_string(),
            "source".to_string(),
        );
        
        assert_eq!(message.retry_count, 0);
        message.increment_retry();
        assert_eq!(message.retry_count, 1);
    }

    #[test]
    fn test_dtn_message_backoff_calculation() {
        let mut message = DtnMessage::new(
            b"test".to_vec(),
            "dest".to_string(),
            "source".to_string(),
        );
        
        let delay1 = message.calculate_backoff(1000, 300000);
        message.increment_retry();
        let delay2 = message.calculate_backoff(1000, 300000);
        
        assert!(delay2 > delay1);
    }

    // ============================================
    // Async Tests for MeshFallback
    // ============================================

    #[tokio::test]
    async fn test_mesh_fallback_creation() {
        let config = MeshFallbackConfig::default();
        let result = MeshFallback::new(config);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mesh_fallback_default_config() {
        let config = MeshFallbackConfig::default();
        let result = MeshFallback::new(config);
        assert!(result.is_ok());
    }

    // ============================================
    // Async Tests for BleMesh
    // ============================================

    #[tokio::test]
    async fn test_ble_mesh_creation() -> AnyhowResult<()> {
        let config = BleConfig::default();
        let mesh = BleMesh::new(config)?;
        assert!(!mesh.is_advertising());
        assert!(!mesh.is_scanning());
        Ok(())
    }

    #[tokio::test]
    async fn test_ble_mesh_discover_peers_not_initialized() -> AnyhowResult<()> {
        let config = BleConfig::default();
        let mesh = BleMesh::new(config)?;

        let peers = mesh.discover_peers().await;
        assert!(peers.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_ble_mesh_shutdown() -> AnyhowResult<()> {
        let config = BleConfig::default();
        let mesh = BleMesh::new(config)?;

        let result = mesh.shutdown().await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_ble_mesh_get_connected_peers() -> AnyhowResult<()> {
        let config = BleConfig::default();
        let mesh = BleMesh::new(config)?;

        let peers = mesh.get_connected_peers();
        assert!(peers.is_empty());
        Ok(())
    }

    // ============================================
    // Async Tests for MeshtasticBridge
    // ============================================

    #[tokio::test]
    async fn test_meshtastic_bridge_creation() {
        let config = MeshtasticConfig::default();
        let result = MeshtasticBridge::new(config);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_meshtastic_bridge_default_config() -> AnyhowResult<()> {
        let config = MeshtasticConfig::default();
        let bridge = MeshtasticBridge::new(config)?;

        assert!(!bridge.is_connected());
        assert!(bridge.get_subscribed_topics().is_empty());
        Ok(())
    }

    // ============================================
    // Async Tests for DtnStore
    // ============================================

    #[tokio::test]
    async fn test_dtn_store_creation() {
        let temp_dir = std::env::temp_dir();
        let config = DtnStoreConfig::new(temp_dir);
        let result = DtnStore::new(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_dtn_message_status_variants() {
        let statuses = vec![
            DtnMessageStatus::Pending,
            DtnMessageStatus::InTransit,
            DtnMessageStatus::Delivered,
            DtnMessageStatus::Failed,
            DtnMessageStatus::Expired,
        ];
        
        for status in statuses {
            let _ = format!("{:?}", status);
        }
    }

    #[test]
    fn test_dtn_message_status_equality() {
        assert_eq!(DtnMessageStatus::Pending, DtnMessageStatus::Pending);
        assert_eq!(DtnMessageStatus::Delivered, DtnMessageStatus::Delivered);
        assert_ne!(DtnMessageStatus::Pending, DtnMessageStatus::Delivered);
    }

    // ============================================
    // Integration Tests
    // ============================================

    #[tokio::test]
    async fn test_full_mesh_lifecycle() -> AnyhowResult<()> {
        let config = MeshFallbackConfig::default();
        let mut mesh = MeshFallback::new(config)?;

        // Initialize
        let result = mesh.initialize().await;
        // May succeed or fail depending on available networks
        let _ = result;

        // Get status
        let status = mesh.get_status();
        let _ = status;

        // Shutdown
        let result = mesh.shutdown().await;
        assert!(result.is_ok());
        Ok(())
    }

    // ============================================
    // Error Handling Tests
    // ============================================

    #[test]
    fn test_mesh_error_variants() {
        let errors = vec![
            MeshError::NetworkUnavailable("test".to_string()),
            MeshError::ConnectionFailed("test".to_string()),
            MeshError::SendFailed("test".to_string()),
            MeshError::BleError("test".to_string()),
            MeshError::MeshtasticError("test".to_string()),
            MeshError::DtnError("test".to_string()),
            MeshError::AllPathsExhausted,
        ];
        
        for err in errors {
            let msg = err.to_string();
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn test_mesh_result_type() {
        fn success() -> MeshResult<i32> {
            Ok(42)
        }
        
        fn failure() -> MeshResult<i32> {
            Err(MeshError::AllPathsExhausted)
        }
        
        assert!(success().is_ok());
        assert!(failure().is_err());
    }

    // ============================================
    // Edge Case Tests
    // ============================================

    #[test]
    fn test_network_status_with_values() {
        let status = NetworkStatus {
            network_type: NetworkType::Tcp,
            connection_state: ConnectionState::Connected,
            latency_ms: Some(100),
            bandwidth_mbps: Some(10.5),
            available_networks: vec![NetworkType::Tcp, NetworkType::Ble],
        };
        
        assert_eq!(status.latency_ms, Some(100));
        assert_eq!(status.bandwidth_mbps, Some(10.5));
        assert_eq!(status.available_networks.len(), 2);
    }

    #[test]
    fn test_fallback_event_variants() {
        let events = vec![
            FallbackEvent::NetworkChanged(NetworkType::Tcp),
            FallbackEvent::ConnectionEstablished(NetworkType::Quic),
            FallbackEvent::ConnectionLost(NetworkType::Ble),
            FallbackEvent::MessageQueued(vec![1, 2, 3]),
            FallbackEvent::MessageDelivered("id".to_string()),
            FallbackEvent::FallbackTriggered(NetworkType::Meshtastic),
        ];
        
        for event in events {
            let _ = format!("{:?}", event);
        }
    }

    #[test]
    fn test_mesh_command_variants() {
        let commands = vec![
            MeshCommand::SwitchNetwork(NetworkType::Tcp),
            MeshCommand::ForceReconnect,
            MeshCommand::EnableFallback,
            MeshCommand::DisableFallback,
            MeshCommand::GetStatus,
        ];
        
        for cmd in commands {
            let _ = format!("{:?}", cmd);
        }
    }

    #[test]
    fn test_mesh_message_variants() {
        let messages = vec![
            MeshMessage::Data {
                payload: Bytes::from("test"),
                priority: 0,
                source: "src".to_string(),
                destination: "dst".to_string(),
            },
            MeshMessage::Control {
                command: MeshCommand::GetStatus,
            },
            MeshMessage::HealthCheck {
                agent_id: "agent".to_string(),
            },
        ];
        
        for msg in messages {
            let _ = format!("{:?}", msg);
        }
    }

    #[test]
    fn test_ble_peer_creation() {
        let peer = BlePeer::new("AA:BB:CC:DD:EE:FF".to_string(), Some("Test Device".to_string()));
        
        assert!(!peer.id.is_empty());
        assert_eq!(peer.address, "AA:BB:CC:DD:EE:FF");
        assert_eq!(peer.name, Some("Test Device".to_string()));
        assert!(!peer.connected);
    }

    #[test]
    fn test_ble_mesh_message_creation() {
        let msg = BleMeshMessage::new(
            "source-1".to_string(),
            "dest-1".to_string(),
            b"payload".to_vec(),
        );
        
        assert!(!msg.message_id.is_empty());
        assert_eq!(msg.source_id, "source-1");
        assert_eq!(msg.destination_id, "dest-1");
        assert_eq!(msg.hop_count, 0);
    }

    #[test]
    fn test_meshtastic_message_creation() {
        let msg = MeshtasticMessage::new(123, 456, b"test".to_vec());
        
        assert_eq!(msg.from_node, 123);
        assert_eq!(msg.to_node, 456);
        assert_eq!(msg.payload, b"test");
        assert_eq!(msg.hop_limit, 3);
    }

    #[test]
    fn test_meshtastic_message_serialization() {
        let msg = MeshtasticMessage::new(123, 456, b"test".to_vec());
        
        let payload = msg.to_mqtt_payload();
        assert!(!payload.is_empty());
        
        let recovered = MeshtasticMessage::from_mqtt_payload(&payload);
        assert!(recovered.is_some());
    }

    #[tokio::test]
    async fn test_ble_mesh_concurrent_operations() -> AnyhowResult<()> {
        use std::sync::Arc;

        let config = BleConfig::default();
        let mesh = Arc::new(BleMesh::new(config)?);

        let mut handles = vec![];

        for _ in 0..10 {
            let m = Arc::clone(&mesh);
            let handle = tokio::spawn(async move {
                let _ = m.discover_peers().await;
                let _ = m.get_connected_peers();
                m.is_advertising()
            });
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.await?;
        }
        Ok(())
    }

    #[test]
    fn test_dtn_message_expiration() {
        let mut message = DtnMessage::new(
            b"test".to_vec(),
            "dest".to_string(),
            "source".to_string(),
        );
        
        // Set expiration in the past
        message.expires_at = Utc::now() - chrono::Duration::seconds(1);
        
        assert!(message.is_expired());
    }

    #[test]
    fn test_network_type_display() {
        assert_eq!(format!("{:?}", NetworkType::Quic), "Quic");
        assert_eq!(format!("{:?}", NetworkType::Tcp), "Tcp");
        assert_eq!(format!("{:?}", NetworkType::Ble), "Ble");
        assert_eq!(format!("{:?}", NetworkType::Meshtastic), "Meshtastic");
        assert_eq!(format!("{:?}", NetworkType::Offline), "Offline");
    }

    #[test]
    fn test_config_cloning() {
        let mesh_config = MeshFallbackConfig::default();
        let _ = mesh_config.clone();
        
        let ble_config = BleConfig::default();
        let _ = ble_config.clone();
        
        let meshtastic_config = MeshtasticConfig::default();
        let _ = meshtastic_config.clone();
    }

    #[tokio::test]
    async fn test_dtn_store_operations() -> AnyhowResult<()> {
        let temp_dir = std::env::temp_dir();
        let config = DtnStoreConfig::new(temp_dir);
        let store = DtnStore::new(config)?;

        // Store a message
        let id = store.store(b"test payload", "recipient")?;
        assert_eq!(store.get_message_count(), 1);

        // Retrieve the message
        let message = store.retrieve(&id);
        assert!(message.is_some());

        // Get pending messages
        let pending = store.get_pending_messages();
        assert_eq!(pending.len(), 1);

        // Delete the message
        store.delete(&id)?;
        assert_eq!(store.get_message_count(), 0);
        Ok(())
    }

    #[test]
    fn test_dtn_metadata_default() {
        let metadata: DtnMetadata = Default::default();
        assert_eq!(metadata.original_size, 0);
        assert!(!metadata.compressed);
        assert!(metadata.encryption.is_none());
        assert!(metadata.routing_info.is_none());
    }

    #[test]
    fn test_ble_config_custom_values() {
        let config = BleConfig {
            device_name: "Custom Device".to_string(),
            max_connections: 10,
            advertise_interval_ms: 200,
            scan_duration_secs: 20,
            ..Default::default()
        };
        
        assert_eq!(config.device_name, "Custom Device");
        assert_eq!(config.max_connections, 10);
    }

    #[test]
    fn test_meshtastic_config_builder() {
        let config = MeshtasticConfig::new(
            "custom.meshtastic.org",
            "custom",
            "device123",
        );
        
        assert_eq!(config.mqtt_broker, "custom.meshtastic.org");
        assert_eq!(config.root_topic, "custom");
        assert_eq!(config.device_id, "device123");
    }

    #[test]
    fn test_meshtastic_config_with_credentials() {
        let config = MeshtasticConfig::default()
            .with_credentials("user", "pass");
        
        assert_eq!(config.username, Some("user".to_string()));
    }

    #[test]
    fn test_meshtastic_config_with_tls() {
        let config = MeshtasticConfig::default()
            .with_tls();
        
        assert!(config.use_tls);
        assert_eq!(config.mqtt_port, 8883);
    }

    #[tokio::test]
    async fn test_mesh_fallback_shutdown_without_init() -> AnyhowResult<()> {
        let config = MeshFallbackConfig::default();
        let mut mesh = MeshFallback::new(config)?;

        // Should be safe to shutdown without initializing
        let result = mesh.shutdown().await;
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_dtn_store_config_new() {
        let path = std::path::PathBuf::from("/tmp/test_dtn");
        let config = DtnStoreConfig::new(path.clone());
        
        assert_eq!(config.store_path, path);
        assert_eq!(config.max_messages, 10000); // Default value preserved
    }

    #[test]
    fn test_meshtastic_device_info_creation() {
        let info = MeshtasticDeviceInfo {
            node_id: 12345,
            user: None,
            position: None,
            last_heard: 0,
            num_channels: 0,
            model: "Test".to_string(),
            firmware_version: "1.0".to_string(),
        };
        
        assert_eq!(info.node_id, 12345);
    }

    #[test]
    fn test_meshtastic_user_creation() {
        let user = MeshtasticUser {
            id: "1234".to_string(),
            long_name: "Test User".to_string(),
            short_name: "TU".to_string(),
        };
        
        assert_eq!(user.long_name, "Test User");
    }

    #[test]
    fn test_meshtastic_position_creation() {
        let pos = MeshtasticPosition {
            latitude: 37.7749,
            longitude: -122.4194,
            altitude: 100,
            time: 1234567890,
        };
        
        assert_eq!(pos.latitude, 37.7749);
        assert_eq!(pos.longitude, -122.4194);
    }
}
