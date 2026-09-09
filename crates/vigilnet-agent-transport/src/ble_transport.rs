use crate::{AgentConnection, TransportKind};
use async_trait::async_trait;
use bytes::Bytes;
use std::net::SocketAddr;
use tracing::{info, warn};

use crate::transport::{AgentTransport, TransportError, TransportResult};

pub struct BleAgentTransport {
    available: bool,
}

impl BleAgentTransport {
    pub fn new() -> Self {
        Self { available: false }
    }

    pub fn is_available(&self) -> bool {
        self.available
    }
}

impl Default for BleAgentTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AgentTransport for BleAgentTransport {
    async fn bind(&mut self) -> TransportResult<()> {
        if !self.available {
            warn!("BLE transport not available on this platform");
            return Err(TransportError::NotAvailable(
                "BLE transport not yet implemented".into(),
            ));
        }
        Ok(())
    }

    async fn connect(&self, _addr: SocketAddr) -> TransportResult<Box<dyn AgentConnection>> {
        Err(TransportError::NotAvailable(
            "BLE transport not yet implemented".into(),
        ))
    }

    async fn accept(&self) -> TransportResult<Box<dyn AgentConnection>> {
        Err(TransportError::NotAvailable(
            "BLE transport not yet implemented".into(),
        ))
    }

    async fn shutdown(&mut self) -> TransportResult<()> {
        info!("BLE transport shut down");
        Ok(())
    }

    fn transport_kind(&self) -> TransportKind {
        TransportKind::Ble
    }

    fn local_addr(&self) -> TransportResult<SocketAddr> {
        Err(TransportError::NotAvailable(
            "BLE does not use socket addresses".into(),
        ))
    }
}

pub struct BleConnection;

#[async_trait]
impl AgentConnection for BleConnection {
    async fn send(&self, _data: Bytes) -> TransportResult<()> {
        Err(TransportError::NotAvailable(
            "BLE transport not yet implemented".into(),
        ))
    }

    async fn recv(&self) -> TransportResult<Bytes> {
        Err(TransportError::NotAvailable(
            "BLE transport not yet implemented".into(),
        ))
    }

    fn remote_addr(&self) -> SocketAddr {
        SocketAddr::from(([0, 0, 0, 0], 0))
    }

    fn transport_kind(&self) -> TransportKind {
        TransportKind::Ble
    }

    async fn close(&self) -> TransportResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================
    // Unit Tests for Core Functionality
    // ============================================

    #[test]
    fn test_ble_transport_creation() {
        let transport = BleAgentTransport::new();
        assert!(!transport.is_available());
        assert_eq!(transport.transport_kind(), TransportKind::Ble);
    }

    #[test]
    fn test_ble_transport_default() {
        let transport: BleAgentTransport = Default::default();
        assert!(!transport.is_available());
    }

    #[test]
    fn test_ble_transport_kind() {
        let transport = BleAgentTransport::new();
        assert_eq!(transport.transport_kind(), TransportKind::Ble);
    }

    // ============================================
    // Async Tests for Bind
    // ============================================

    #[tokio::test]
    async fn test_ble_bind_not_available() {
        let mut transport = BleAgentTransport::new();
        let result = transport.bind().await;
        
        assert!(result.is_err());
        match result {
            Err(TransportError::NotAvailable(msg)) => {
                assert!(msg.contains("BLE"));
                assert!(msg.contains("not yet implemented"));
            }
            _ => panic!("Expected NotAvailable error"),
        }
    }

    // ============================================
    // Async Tests for Connect
    // ============================================

    #[tokio::test]
    async fn test_ble_connect_not_available() {
        let transport = BleAgentTransport::new();
        let addr: SocketAddr = "127.0.0.1:8080".parse().expect("hardcoded address should parse");
        let result = transport.connect(addr).await;
        
        assert!(result.is_err());
        match result {
            Err(TransportError::NotAvailable(msg)) => {
                assert!(msg.contains("BLE"));
            }
            _ => panic!("Expected NotAvailable error"),
        }
    }

    // ============================================
    // Async Tests for Accept
    // ============================================

    #[tokio::test]
    async fn test_ble_accept_not_available() {
        let transport = BleAgentTransport::new();
        let result = transport.accept().await;
        
        assert!(result.is_err());
        match result {
            Err(TransportError::NotAvailable(msg)) => {
                assert!(msg.contains("BLE"));
            }
            _ => panic!("Expected NotAvailable error"),
        }
    }

    // ============================================
    // Async Tests for Shutdown
    // ============================================

    #[tokio::test]
    async fn test_ble_shutdown_success() {
        let mut transport = BleAgentTransport::new();
        let result = transport.shutdown().await;
        
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ble_shutdown_idempotent() {
        let mut transport = BleAgentTransport::new();
        
        // Multiple shutdowns should all succeed
        for _ in 0..5 {
            let result = transport.shutdown().await;
            assert!(result.is_ok());
        }
    }

    // ============================================
    // Tests for Local Address
    // ============================================

    #[test]
    fn test_ble_local_addr_not_available() {
        let transport = BleAgentTransport::new();
        let result = transport.local_addr();
        
        assert!(result.is_err());
        match result {
            Err(TransportError::NotAvailable(msg)) => {
                assert!(msg.contains("BLE"));
                assert!(msg.contains("does not use socket addresses"));
            }
            _ => panic!("Expected NotAvailable error"),
        }
    }

    // ============================================
    // BleConnection Tests
    // ============================================

    #[tokio::test]
    async fn test_ble_connection_send() {
        let conn = BleConnection;
        let data = Bytes::from("test data");
        let result = conn.send(data).await;
        
        assert!(result.is_err());
        match result {
            Err(TransportError::NotAvailable(_)) => {}
            _ => panic!("Expected NotAvailable error"),
        }
    }

    #[tokio::test]
    async fn test_ble_connection_recv() {
        let conn = BleConnection;
        let result = conn.recv().await;
        
        assert!(result.is_err());
        match result {
            Err(TransportError::NotAvailable(_)) => {}
            _ => panic!("Expected NotAvailable error"),
        }
    }

    #[test]
    fn test_ble_connection_remote_addr() {
        let conn = BleConnection;
        let addr = conn.remote_addr();
        
        assert_eq!(addr, SocketAddr::from(([0, 0, 0, 0], 0)));
    }

    #[test]
    fn test_ble_connection_transport_kind() {
        let conn = BleConnection;
        assert_eq!(conn.transport_kind(), TransportKind::Ble);
    }

    #[tokio::test]
    async fn test_ble_connection_close() {
        let conn = BleConnection;
        let result = conn.close().await;
        
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ble_connection_close_idempotent() {
        let conn = BleConnection;
        
        // Multiple closes should all succeed
        for _ in 0..5 {
            let result = conn.close().await;
            assert!(result.is_ok());
        }
    }

    // ============================================
    // Integration Tests
    // ============================================

    #[tokio::test]
    async fn test_ble_full_lifecycle() {
        let mut transport = BleAgentTransport::new();
        
        // Try to bind (will fail on most platforms)
        let bind_result = transport.bind().await;
        assert!(bind_result.is_err());
        
        // Try to connect (will fail)
        let addr: SocketAddr = "127.0.0.1:8080".parse().expect("hardcoded address should parse");
        let connect_result = transport.connect(addr).await;
        assert!(connect_result.is_err());
        
        // Try to accept (will fail)
        let accept_result = transport.accept().await;
        assert!(accept_result.is_err());
        
        // Get local address (will fail)
        let local_addr_result = transport.local_addr();
        assert!(local_addr_result.is_err());
        
        // Shutdown (should succeed)
        let shutdown_result = transport.shutdown().await;
        assert!(shutdown_result.is_ok());
        
        // Verify transport kind
        assert_eq!(transport.transport_kind(), TransportKind::Ble);
    }

    #[tokio::test]
    async fn test_ble_connection_full_operations() {
        let conn = BleConnection;
        
        // All operations should return the expected errors
        assert_eq!(conn.transport_kind(), TransportKind::Ble);
        assert_eq!(conn.remote_addr(), SocketAddr::from(([0, 0, 0, 0], 0)));
        
        let send_result = conn.send(Bytes::from("test")).await;
        assert!(send_result.is_err());
        
        let recv_result = conn.recv().await;
        assert!(recv_result.is_err());
        
        let close_result = conn.close().await;
        assert!(close_result.is_ok());
    }

    // ============================================
    // Error Handling Tests
    // ============================================

    #[tokio::test]
    async fn test_ble_error_messages() {
        let transport = BleAgentTransport::new();
        let addr: SocketAddr = "127.0.0.1:8080".parse().expect("hardcoded address should parse");
        
        // Test all methods that should return NotAvailable
        let bind_err = transport.bind().await;
        let connect_err = transport.connect(addr).await;
        let accept_err = transport.accept().await;
        let local_addr_err = transport.local_addr();
        
        // All should be NotAvailable errors
        assert!(matches!(bind_err, Err(TransportError::NotAvailable(_))));
        assert!(matches!(connect_err, Err(TransportError::NotAvailable(_))));
        assert!(matches!(accept_err, Err(TransportError::NotAvailable(_))));
        assert!(matches!(local_addr_err, Err(TransportError::NotAvailable(_))));
        
        // Verify error messages contain expected text
        if let Err(e) = bind_err {
            assert!(e.to_string().contains("BLE"));
        }
        if let Err(e) = connect_err {
            assert!(e.to_string().contains("BLE"));
        }
        if let Err(e) = accept_err {
            assert!(e.to_string().contains("BLE"));
        }
        if let Err(e) = local_addr_err {
            assert!(e.to_string().contains("BLE"));
        }
    }

    #[tokio::test]
    async fn test_ble_connection_error_messages() {
        let conn = BleConnection;
        
        let send_err = conn.send(Bytes::from("test")).await;
        let recv_err = conn.recv().await;
        
        assert!(matches!(send_err, Err(TransportError::NotAvailable(_))));
        assert!(matches!(recv_err, Err(TransportError::NotAvailable(_))));
        
        if let Err(e) = send_err {
            assert!(e.to_string().contains("BLE"));
        }
        if let Err(e) = recv_err {
            assert!(e.to_string().contains("BLE"));
        }
    }

    // ============================================
    // Edge Case Tests
    // ============================================

    #[tokio::test]
    async fn test_ble_connect_with_any_address() {
        let transport = BleAgentTransport::new();
        
        // Should fail regardless of address
        let addrs = vec![
            "127.0.0.1:8080".parse().expect("hardcoded address should parse"),
            "0.0.0.0:0".parse().expect("hardcoded address should parse"),
            "192.168.1.1:12345".parse().expect("hardcoded address should parse"),
            "[::1]:8080".parse().expect("hardcoded address should parse"),
        ];
        
        for addr in addrs {
            let result = transport.connect(addr).await;
            assert!(result.is_err(), "Should fail for address {}", addr);
        }
    }

    #[tokio::test]
    async fn test_ble_send_empty_data() {
        let conn = BleConnection;
        let result = conn.send(Bytes::new()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_ble_send_large_data() {
        let conn = BleConnection;
        let large_data = Bytes::from(vec![0u8; 1024 * 1024]); // 1MB
        let result = conn.send(large_data).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_ble_transport_clone_behavior() {
        let transport1 = BleAgentTransport::new();
        // BleAgentTransport doesn't implement Clone, but we can verify
        // multiple instances are independent
        let transport2 = BleAgentTransport::new();
        
        assert_eq!(transport1.is_available(), transport2.is_available());
        assert_eq!(transport1.transport_kind(), transport2.transport_kind());
    }

    #[tokio::test]
    async fn test_ble_multiple_instances() {
        let transports: Vec<_> = (0..5).map(|_| BleAgentTransport::new()).collect();
        
        for mut transport in transports {
            assert!(!transport.is_available());
            
            let result = transport.bind().await;
            assert!(result.is_err());
            
            let shutdown_result = transport.shutdown().await;
            assert!(shutdown_result.is_ok());
        }
    }

    #[test]
    fn test_ble_connection_trait_bounds() {
        // Compile-time test that BleConnection implements AgentConnection
        fn check_trait<T: AgentConnection>(_conn: T) {}
        check_trait(BleConnection);
    }

    #[test]
    fn test_ble_transport_trait_bounds() {
        // Compile-time test that BleAgentTransport implements AgentTransport
        fn check_trait<T: AgentTransport>(_transport: T) {}
        check_trait(BleAgentTransport::new());
    }

    #[tokio::test]
    async fn test_ble_concurrent_operations() {
        use std::sync::Arc;
        
        let transport = Arc::new(BleAgentTransport::new());
        let mut handles = vec![];
        
        for _ in 0..10 {
            let t = Arc::clone(&transport);
            let handle = tokio::spawn(async move {
                let addr: SocketAddr = "127.0.0.1:8080".parse().expect("hardcoded address should parse");
                let _ = t.connect(addr).await;
                let _ = t.local_addr();
                t.transport_kind()
            });
            handles.push(handle);
        }
        
        for handle in handles {
            let kind = handle.await.ok();
            assert_eq!(kind, Some(TransportKind::Ble));
        }
    }

    #[test]
    fn test_ble_transport_debug() {
        let transport = BleAgentTransport::new();
        let debug_str = format!("{:?}", transport);
        // Since BleAgentTransport only has a bool field, debug output should be simple
        assert!(!debug_str.is_empty());
    }

    #[test]
    fn test_ble_connection_debug() {
        let conn = BleConnection;
        let debug_str = format!("{:?}", conn);
        // BleConnection is an empty struct
        assert!(!debug_str.is_empty());
    }

    #[tokio::test]
    async fn test_ble_shutdown_after_operations() {
        let mut transport = BleAgentTransport::new();
        let addr: SocketAddr = "127.0.0.1:8080".parse().expect("hardcoded address should parse");
        
        // Try various operations
        let _ = transport.bind().await;
        let _ = transport.connect(addr).await;
        let _ = transport.accept().await;
        let _ = transport.local_addr();
        
        // Shutdown should still work
        let result = transport.shutdown().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ble_connection_send_various_sizes() {
        let conn = BleConnection;
        
        let sizes = vec![0, 1, 100, 1000, 10000];
        
        for size in sizes {
            let data = Bytes::from(vec![0u8; size]);
            let result = conn.send(data).await;
            assert!(result.is_err(), "Should fail for size {}", size);
        }
    }

    #[test]
    fn test_ble_connection_remote_addr_consistency() {
        let conn = BleConnection;
        
        // Should always return the same address
        for _ in 0..10 {
            assert_eq!(conn.remote_addr(), SocketAddr::from(([0, 0, 0, 0], 0)));
        }
    }

    #[tokio::test]
    async fn test_ble_transport_availability_constant() {
        let transport = BleAgentTransport::new();
        
        // Availability should remain constant
        for _ in 0..10 {
            assert!(!transport.is_available());
        }
        
        // Operations shouldn't change availability
        let addr: SocketAddr = "127.0.0.1:8080".parse().expect("hardcoded address should parse");
        let _ = transport.connect(addr).await;
        assert!(!transport.is_available());
    }

    #[tokio::test]
    async fn test_ble_error_consistency() {
        let transport = BleAgentTransport::new();
        let addr: SocketAddr = "127.0.0.1:8080".parse().expect("hardcoded address should parse");
        
        // Multiple calls should return same error type
        for _ in 0..5 {
            let result = transport.connect(addr).await;
            assert!(matches!(result, Err(TransportError::NotAvailable(_))));
        }
    }
}
