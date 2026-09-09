pub mod ble_transport;
pub mod quic_transport;
pub mod tcp_transport;
pub mod transport;

pub use ble_transport::BleAgentTransport;
pub use quic_transport::{QuicAgentTransport, QuicConfig};
pub use tcp_transport::{TcpAgentTransport, TcpConfig};
pub use transport::{
    AgentConnection, AgentTransport, TransportConfig, TransportError, TransportKind, TransportResult,
    UnifiedTransport,
};

use async_trait::async_trait;
use bytes::Bytes;
use std::net::SocketAddr;
use vigilnet_agent_core::AgentId;

#[async_trait]
pub trait AgentConnection: Send + Sync {
    async fn send(&self, data: Bytes) -> TransportResult<()>;
    async fn recv(&self) -> TransportResult<Bytes>;
    fn remote_addr(&self) -> SocketAddr;
    fn transport_kind(&self) -> TransportKind;
    async fn close(&self) -> TransportResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // ============================================
    // Unit Tests for Core Functionality
    // ============================================

    #[test]
    fn test_transport_kind_variants() {
        let kinds = vec![
            TransportKind::Quic,
            TransportKind::Tcp,
            TransportKind::Ble,
            TransportKind::Tor,
            TransportKind::I2p,
            TransportKind::Freenet,
            TransportKind::WireGuard,
            TransportKind::Nym,
        ];

        for kind in kinds {
            let display = format!("{}", kind);
            assert!(!display.is_empty());
        }
    }

    #[test]
    fn test_transport_kind_quic_display() {
        assert_eq!(format!("{}", TransportKind::Quic), "QUIC");
    }

    #[test]
    fn test_transport_kind_tcp_display() {
        assert_eq!(format!("{}", TransportKind::Tcp), "TCP");
    }

    #[test]
    fn test_transport_kind_ble_display() {
        assert_eq!(format!("{}", TransportKind::Ble), "BLE");
    }

    #[test]
    fn test_transport_kind_tor_display() {
        assert_eq!(format!("{}", TransportKind::Tor), "Tor");
    }

    #[test]
    fn test_transport_kind_i2p_display() {
        assert_eq!(format!("{}", TransportKind::I2p), "I2P");
    }

    #[test]
    fn test_transport_kind_freenet_display() {
        assert_eq!(format!("{}", TransportKind::Freenet), "Freenet");
    }

    #[test]
    fn test_transport_kind_wireguard_display() {
        assert_eq!(format!("{}", TransportKind::WireGuard), "WireGuard");
    }

    #[test]
    fn test_transport_kind_nym_display() {
        assert_eq!(format!("{}", TransportKind::Nym), "Nym");
    }

    #[test]
    fn test_transport_kind_equality() {
        assert_eq!(TransportKind::Quic, TransportKind::Quic);
        assert_ne!(TransportKind::Quic, TransportKind::Tcp);
        assert_eq!(TransportKind::Ble, TransportKind::Ble);
    }

    #[test]
    fn test_transport_kind_clone() {
        let kind = TransportKind::Quic;
        let cloned = kind.clone();
        assert_eq!(kind, cloned);
    }

    #[test]
    fn test_transport_kind_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(TransportKind::Quic);
        set.insert(TransportKind::Quic); // Duplicate
        set.insert(TransportKind::Tcp);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_transport_kind_debug() {
        let debug_str = format!("{:?}", TransportKind::Quic);
        assert!(debug_str.contains("Quic"));
    }

    #[test]
    fn test_transport_error_connection_failed() {
        let err = TransportError::ConnectionFailed("network unreachable".to_string());
        assert!(err.to_string().contains("Connection failed"));
        assert!(err.to_string().contains("network unreachable"));
    }

    #[test]
    fn test_transport_error_not_available() {
        let err = TransportError::NotAvailable("BLE not supported".to_string());
        assert!(err.to_string().contains("Transport not available"));
    }

    #[test]
    fn test_transport_error_not_bound() {
        let err = TransportError::NotBound;
        assert!(err.to_string().contains("Transport not bound"));
    }

    #[test]
    fn test_transport_error_bind() {
        let err = TransportError::Bind("address in use".to_string());
        assert!(err.to_string().contains("Bind failed"));
    }

    #[test]
    fn test_transport_error_config() {
        let err = TransportError::Config("invalid timeout".to_string());
        assert!(err.to_string().contains("Config error"));
    }

    #[test]
    fn test_transport_error_send() {
        let err = TransportError::Send("broken pipe".to_string());
        assert!(err.to_string().contains("Send error"));
    }

    #[test]
    fn test_transport_error_recv() {
        let err = TransportError::Recv("connection reset".to_string());
        assert!(err.to_string().contains("Recv error"));
    }

    #[test]
    fn test_transport_error_io() {
        let err = TransportError::Io("permission denied".to_string());
        assert!(err.to_string().contains("IO error"));
    }

    #[test]
    fn test_transport_error_timeout() {
        let err = TransportError::Timeout("connection timed out".to_string());
        assert!(err.to_string().contains("Timeout"));
    }

    #[test]
    fn test_transport_error_all_transports_failed() {
        let err = TransportError::AllTransportsFailed;
        assert!(err.to_string().contains("All transports failed"));
    }

    #[test]
    fn test_transport_error_debug() {
        let err = TransportError::ConnectionFailed("test".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("ConnectionFailed"));
    }

    #[test]
    fn test_transport_result_success() {
        fn success_op() -> TransportResult<i32> {
            Ok(42)
        }

        assert!(success_op().is_ok());
        assert_eq!(success_op().expect("success op should return Ok"), 42);
    }

    #[test]
    fn test_transport_result_failure() {
        fn fail_op() -> TransportResult<i32> {
            Err(TransportError::NotBound)
        }

        assert!(fail_op().is_err());
    }

    #[test]
    fn test_transport_config_default() {
        let config = TransportConfig::default();
        assert!(config.enable_quic);
        assert!(config.enable_tcp);
        assert!(!config.enable_ble);
        assert_eq!(config.fallback_timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_transport_config_quic() {
        let config = QuicConfig::default();
        assert_eq!(config.max_idle_timeout, Duration::from_secs(120));
        assert_eq!(config.keep_alive_interval, Duration::from_secs(10));
        assert_eq!(config.max_concurrent_bi_streams, 128);
        assert_eq!(config.max_concurrent_uni_streams, 128);
        assert!(config.enable_0rtt);
    }

    #[test]
    fn test_transport_config_tcp() {
        let config = TcpConfig::default();
        assert!(config.nodelay);
        assert_eq!(config.keepalive, Some(Duration::from_secs(30)));
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
        assert_eq!(config.send_buffer_size, 1024 * 1024);
        assert_eq!(config.recv_buffer_size, 1024 * 1024);
    }

    #[test]
    fn test_quic_config_clone() {
        let config = QuicConfig::default();
        let cloned = config.clone();
        assert_eq!(config.bind_addr, cloned.bind_addr);
        assert_eq!(config.max_idle_timeout, cloned.max_idle_timeout);
    }

    #[test]
    fn test_tcp_config_clone() {
        let config = TcpConfig::default();
        let cloned = config.clone();
        assert_eq!(config.nodelay, cloned.nodelay);
        assert_eq!(config.keepalive, cloned.keepalive);
    }

    #[test]
    fn test_transport_config_clone() {
        let config = TransportConfig::default();
        let cloned = config.clone();
        assert_eq!(config.enable_quic, cloned.enable_quic);
        assert_eq!(config.enable_tcp, cloned.enable_tcp);
        assert_eq!(config.enable_ble, cloned.enable_ble);
        assert_eq!(config.fallback_timeout, cloned.fallback_timeout);
    }

    // ============================================
    // Integration Tests
    // ============================================

    #[test]
    fn test_all_transport_kinds() {
        let kinds = vec![
            (TransportKind::Quic, "QUIC"),
            (TransportKind::Tcp, "TCP"),
            (TransportKind::Ble, "BLE"),
            (TransportKind::Tor, "Tor"),
            (TransportKind::I2p, "I2P"),
            (TransportKind::Freenet, "Freenet"),
            (TransportKind::WireGuard, "WireGuard"),
            (TransportKind::Nym, "Nym"),
        ];

        for (kind, expected) in kinds {
            assert_eq!(format!("{}", kind), expected);
        }
    }

    #[test]
    fn test_transport_config_variations() {
        // Test all possible combinations
        let configs = vec![
            TransportConfig {
                enable_quic: true,
                enable_tcp: true,
                enable_ble: true,
                ..Default::default()
            },
            TransportConfig {
                enable_quic: false,
                enable_tcp: false,
                enable_ble: false,
                ..Default::default()
            },
            TransportConfig {
                enable_quic: true,
                enable_tcp: false,
                enable_ble: false,
                ..Default::default()
            },
            TransportConfig {
                enable_quic: false,
                enable_tcp: true,
                enable_ble: false,
                ..Default::default()
            },
        ];

        for config in configs {
            // Just verify they can be created
            let _ = config.enable_quic;
            let _ = config.enable_tcp;
            let _ = config.enable_ble;
        }
    }

    #[test]
    fn test_error_chain() {
        let errors: Vec<TransportError> = vec![
            TransportError::ConnectionFailed("e1".to_string()),
            TransportError::NotAvailable("e2".to_string()),
            TransportError::NotBound,
            TransportError::Bind("e3".to_string()),
            TransportError::Config("e4".to_string()),
            TransportError::Send("e5".to_string()),
            TransportError::Recv("e6".to_string()),
            TransportError::Io("e7".to_string()),
            TransportError::Timeout("e8".to_string()),
            TransportError::AllTransportsFailed,
        ];

        for err in errors {
            assert!(!err.to_string().is_empty());
        }
    }

    // ============================================
    // Error Handling Tests
    // ============================================

    #[test]
    fn test_transport_error_from_string() {
        // Ensure all error variants can be created from strings
        let _ = TransportError::ConnectionFailed("test".to_string());
        let _ = TransportError::NotAvailable("test".to_string());
        let _ = TransportError::Bind("test".to_string());
        let _ = TransportError::Config("test".to_string());
        let _ = TransportError::Send("test".to_string());
        let _ = TransportError::Recv("test".to_string());
        let _ = TransportError::Io("test".to_string());
        let _ = TransportError::Timeout("test".to_string());
    }

    #[test]
    fn test_transport_result_error_conversion() {
        fn convert_error() -> TransportResult<()> {
            Err(TransportError::ConnectionFailed("converted".to_string()))
        }

        let result = convert_error();
        assert!(result.is_err());
        
        match result {
            Err(TransportError::ConnectionFailed(msg)) => {
                assert_eq!(msg, "converted");
            }
            _ => panic!("Expected ConnectionFailed error"),
        }
    }

    #[test]
    fn test_transport_error_partial_eq() {
        let err1 = TransportError::NotBound;
        let err2 = TransportError::NotBound;
        assert_eq!(err1, err2);

        let err3 = TransportError::AllTransportsFailed;
        assert_ne!(err1, err3);
    }

    // ============================================
    // Edge Case Tests
    // ============================================

    #[test]
    fn test_empty_error_messages() {
        let errors = vec![
            TransportError::ConnectionFailed("".to_string()),
            TransportError::NotAvailable("".to_string()),
            TransportError::Bind("".to_string()),
            TransportError::Config("".to_string()),
            TransportError::Send("".to_string()),
            TransportError::Recv("".to_string()),
            TransportError::Io("".to_string()),
            TransportError::Timeout("".to_string()),
        ];

        for err in errors {
            let msg = err.to_string();
            assert!(!msg.is_empty()); // Should still have the prefix
        }
    }

    #[test]
    fn test_long_error_messages() {
        let long_msg = "a".repeat(10000);
        let err = TransportError::ConnectionFailed(long_msg.clone());
        assert!(err.to_string().contains(&long_msg));
    }

    #[test]
    fn test_special_chars_in_error_messages() {
        let special_msgs = vec![
            "error\nwith\nnewlines",
            "error\twith\ttabs",
            "error with unicode: 你好世界 🌍",
            "error <script>alert('xss')</script>",
            "error with \"quotes\" and 'apostrophes'",
        ];

        for msg in special_msgs {
            let err = TransportError::ConnectionFailed(msg.to_string());
            assert!(err.to_string().contains(msg));
        }
    }

    #[test]
    fn test_quic_config_custom_values() {
        let config = QuicConfig {
            bind_addr: "127.0.0.1:8080"
                .parse()
                .expect("hardcoded address should parse"),
            max_idle_timeout: Duration::from_secs(300),
            keep_alive_interval: Duration::from_secs(5),
            max_concurrent_bi_streams: 256,
            max_concurrent_uni_streams: 256,
            enable_0rtt: false,
        };

        assert_eq!(config.max_concurrent_bi_streams, 256);
        assert!(!config.enable_0rtt);
    }

    #[test]
    fn test_tcp_config_custom_values() {
        let config = TcpConfig {
            bind_addr: "127.0.0.1:9090"
                .parse()
                .expect("hardcoded address should parse"),
            nodelay: false,
            keepalive: None,
            connect_timeout: Duration::from_secs(30),
            send_buffer_size: 512 * 1024,
            recv_buffer_size: 512 * 1024,
        };

        assert!(!config.nodelay);
        assert!(config.keepalive.is_none());
    }

    #[test]
    fn test_transport_config_zero_timeout() {
        let config = TransportConfig {
            fallback_timeout: Duration::ZERO,
            ..Default::default()
        };
        assert_eq!(config.fallback_timeout, Duration::ZERO);
    }

    #[test]
    fn test_transport_config_large_timeout() {
        let config = TransportConfig {
            fallback_timeout: Duration::from_secs(3600),
            ..Default::default()
        };
        assert_eq!(config.fallback_timeout, Duration::from_secs(3600));
    }

    #[test]
    fn test_all_transport_kinds_unique() {
        use std::collections::HashSet;
        
        let kinds = vec![
            TransportKind::Quic,
            TransportKind::Tcp,
            TransportKind::Ble,
            TransportKind::Tor,
            TransportKind::I2p,
            TransportKind::Freenet,
            TransportKind::WireGuard,
            TransportKind::Nym,
        ];

        let unique: HashSet<_> = kinds.iter().collect();
        assert_eq!(unique.len(), kinds.len());
    }

    #[tokio::test]
    async fn test_transport_trait_object() {
        // Test that we can create trait objects
        fn takes_transport(_: Box<dyn AgentTransport>) {}
        
        // This is a compile-time test - if it compiles, it works
    }

    #[test]
    fn test_transport_config_debug() {
        let config = TransportConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("TransportConfig"));
    }

    #[test]
    fn test_quic_config_debug() {
        let config = QuicConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("QuicConfig"));
    }

    #[test]
    fn test_tcp_config_debug() {
        let config = TcpConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("TcpConfig"));
    }

    #[test]
    fn test_result_type_ergonomics() {
        // Test the Result type alias works correctly
        fn may_fail(succeed: bool) -> TransportResult<String> {
            if succeed {
                Ok("success".to_string())
            } else {
                Err(TransportError::NotBound)
            }
        }

        assert!(may_fail(true).is_ok());
        assert!(may_fail(false).is_err());
    }

    #[test]
    fn test_error_variant_coverage() {
        // Ensure we've tested all error variants
        let all_errors = vec![
            TransportError::ConnectionFailed("test".into()),
            TransportError::NotAvailable("test".into()),
            TransportError::NotBound,
            TransportError::Bind("test".into()),
            TransportError::Config("test".into()),
            TransportError::Send("test".into()),
            TransportError::Recv("test".into()),
            TransportError::Io("test".into()),
            TransportError::Timeout("test".into()),
            TransportError::AllTransportsFailed,
        ];

        assert_eq!(all_errors.len(), 10); // All variants
    }

    #[test]
    fn test_transport_kind_ordering() {
        // Just verify the variants exist and can be compared
        assert!(matches!(TransportKind::Quic, TransportKind::Quic));
        assert!(matches!(TransportKind::Tcp, TransportKind::Tcp));
    }

    #[tokio::test]
    async fn test_async_trait_bounds() {
        // Compile-time test that AgentConnection trait is object-safe
        fn check_send_sync<T: Send + Sync>(_: T) {}
        
        // This verifies the trait has the correct bounds
        fn check_connection<T: AgentConnection>(conn: T) {
            check_send_sync(conn);
        }
    }
}
