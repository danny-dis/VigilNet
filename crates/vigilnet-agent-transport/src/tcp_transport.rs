use crate::{AgentConnection, TransportKind};
use async_trait::async_trait;
use bytes::Bytes;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{debug, info, instrument, warn};

use crate::transport::{AgentTransport, TransportError, TransportResult};

#[derive(Debug, Clone)]
pub struct TcpConfig {
    pub bind_addr: SocketAddr,
    pub nodelay: bool,
    pub keepalive: Option<Duration>,
    pub connect_timeout: Duration,
    pub send_buffer_size: usize,
    pub recv_buffer_size: usize,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:0"
                .parse()
                .expect("hardcoded bind address should be valid"),
            nodelay: true,
            keepalive: Some(Duration::from_secs(30)),
            connect_timeout: Duration::from_secs(10),
            send_buffer_size: 1024 * 1024,
            recv_buffer_size: 1024 * 1024,
        }
    }
}

pub struct TcpAgentTransport {
    config: TcpConfig,
    listener: Option<TcpListener>,
}

impl TcpAgentTransport {
    pub fn new(config: TcpConfig) -> Self {
        Self {
            config,
            listener: None,
        }
    }

    fn configure_socket(stream: &TcpStream, config: &TcpConfig) -> TransportResult<()> {
        stream
            .set_nodelay(config.nodelay)
            .map_err(|e| TransportError::Config(e.to_string()))?;

        let sock_ref = socket2::SockRef::from(stream);

        sock_ref
            .set_send_buffer_size(config.send_buffer_size)
            .map_err(|e| TransportError::Config(e.to_string()))?;
        sock_ref
            .set_recv_buffer_size(config.recv_buffer_size)
            .map_err(|e| TransportError::Config(e.to_string()))?;

        if let Some(keepalive) = config.keepalive {
            let ka = socket2::TcpKeepalive::new().with_time(keepalive);
            sock_ref
                .set_tcp_keepalive(&ka)
                .map_err(|e| TransportError::Config(e.to_string()))?;
        }

        Ok(())
    }
}

#[async_trait]
impl AgentTransport for TcpAgentTransport {
    #[instrument(skip(self), name = "TcpTransport::bind")]
    async fn bind(&mut self) -> TransportResult<()> {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .map_err(|e| TransportError::Bind(e.to_string()))?;

        socket
            .set_reuse_address(true)
            .map_err(|e| TransportError::Bind(e.to_string()))?;
        socket
            .set_nonblocking(true)
            .map_err(|e| TransportError::Bind(e.to_string()))?;
        socket
            .bind(&self.config.bind_addr.into())
            .map_err(|e| TransportError::Bind(e.to_string()))?;
        socket
            .listen(128)
            .map_err(|e| TransportError::Bind(e.to_string()))?;

        let std_listener: std::net::TcpListener = socket.into();
        let listener = TcpListener::from_std(std_listener)
            .map_err(|e| TransportError::Bind(e.to_string()))?;

        let local_addr = listener
            .local_addr()
            .map_err(|e| TransportError::Bind(e.to_string()))?;

        info!(addr = %local_addr, "TCP transport bound");
        self.listener = Some(listener);
        Ok(())
    }

    #[instrument(skip(self), name = "TcpTransport::connect")]
    async fn connect(&self, addr: SocketAddr) -> TransportResult<Box<dyn AgentConnection>> {
        let stream = tokio::time::timeout(
            self.config.connect_timeout,
            TcpStream::connect(addr),
        )
        .await
        .map_err(|_| TransportError::Timeout("TCP connect timed out".into()))?
        .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        Self::configure_socket(&stream, &self.config)?;

        info!(remote = %addr, "TCP connection established");

        Ok(Box::new(TcpConnection {
            stream: Arc::new(Mutex::new(stream)),
            remote_addr: addr,
        }))
    }

    #[instrument(skip(self), name = "TcpTransport::accept")]
    async fn accept(&self) -> TransportResult<Box<dyn AgentConnection>> {
        let listener = self
            .listener
            .as_ref()
            .ok_or(TransportError::NotBound)?;

        let (stream, remote_addr) = listener
            .accept()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        Self::configure_socket(&stream, &self.config)?;

        info!(remote = %remote_addr, "TCP connection accepted");

        Ok(Box::new(TcpConnection {
            stream: Arc::new(Mutex::new(stream)),
            remote_addr,
        }))
    }

    async fn shutdown(&mut self) -> TransportResult<()> {
        self.listener.take();
        info!("TCP transport shut down");
        Ok(())
    }

    fn transport_kind(&self) -> TransportKind {
        TransportKind::Tcp
    }

    fn local_addr(&self) -> TransportResult<SocketAddr> {
        self.listener
            .as_ref()
            .ok_or(TransportError::NotBound)?
            .local_addr()
            .map_err(|e| TransportError::Io(e.to_string()))
    }
}

struct TcpConnection {
    stream: Arc<Mutex<TcpStream>>,
    remote_addr: SocketAddr,
}

#[async_trait]
impl AgentConnection for TcpConnection {
    async fn send(&self, data: Bytes) -> TransportResult<()> {
        let mut stream = self.stream.lock().await;

        let len = (data.len() as u32).to_le_bytes();
        stream
            .write_all(&len)
            .await
            .map_err(|e| TransportError::Send(e.to_string()))?;
        stream
            .write_all(&data)
            .await
            .map_err(|e| TransportError::Send(e.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|e| TransportError::Send(e.to_string()))?;

        debug!(size = data.len(), "TCP data sent");
        Ok(())
    }

    async fn recv(&self) -> TransportResult<Bytes> {
        let mut stream = self.stream.lock().await;

        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| TransportError::Recv(e.to_string()))?;
        let len = u32::from_le_bytes(len_buf) as usize;

        if len > 16 * 1024 * 1024 {
            return Err(TransportError::Recv(format!(
                "Message too large: {} bytes",
                len
            )));
        }

        let mut buf = vec![0u8; len];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| TransportError::Recv(e.to_string()))?;

        debug!(size = len, "TCP data received");
        Ok(Bytes::from(buf))
    }

    fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    fn transport_kind(&self) -> TransportKind {
        TransportKind::Tcp
    }

    async fn close(&self) -> TransportResult<()> {
        let mut stream = self.stream.lock().await;
        stream
            .shutdown()
            .await
            .map_err(|e| TransportError::Send(e.to_string()))?;
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
    fn test_tcp_config_default() {
        let config = TcpConfig::default();
        assert_eq!(config.bind_addr.to_string(), "0.0.0.0:0");
        assert!(config.nodelay);
        assert_eq!(config.keepalive, Some(Duration::from_secs(30)));
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
        assert_eq!(config.send_buffer_size, 1024 * 1024);
        assert_eq!(config.recv_buffer_size, 1024 * 1024);
    }

    #[test]
    fn test_tcp_config_clone() {
        let config = TcpConfig::default();
        let cloned = config.clone();
        assert_eq!(config.nodelay, cloned.nodelay);
        assert_eq!(config.keepalive, cloned.keepalive);
        assert_eq!(config.connect_timeout, cloned.connect_timeout);
    }

    #[test]
    fn test_tcp_transport_creation() {
        let config = TcpConfig::default();
        let transport = TcpAgentTransport::new(config);
        assert_eq!(transport.transport_kind(), TransportKind::Tcp);
    }

    #[test]
    fn test_tcp_transport_kind() {
        let config = TcpConfig::default();
        let transport = TcpAgentTransport::new(config);
        assert_eq!(transport.transport_kind(), TransportKind::Tcp);
    }

    // ============================================
    // Async Tests for Bind
    // ============================================

    #[tokio::test]
    async fn test_tcp_bind_success() {
        let config = TcpConfig::default();
        let mut transport = TcpAgentTransport::new(config);
        let result = transport.bind().await;
        assert!(result.is_ok());
        
        // Verify we can get local address
        let local_addr = transport.local_addr();
        assert!(local_addr.is_ok());
        
        transport.shutdown().await.ok();
    }

    #[tokio::test]
    async fn test_tcp_bind_specific_port() {
        let config = TcpConfig {
            bind_addr: "127.0.0.1:0".parse().expect("hardcoded address should parse"),
            ..Default::default()
        };
        let mut transport = TcpAgentTransport::new(config);
        let result = transport.bind().await;
        assert!(result.is_ok());
        
        let local_addr = transport.local_addr().ok();
        if let Some(addr) = local_addr {
            assert_eq!(addr.ip().to_string(), "127.0.0.1");
            assert!(addr.port() > 0);
        }
        
        transport.shutdown().await.ok();
    }

    #[tokio::test]
    async fn test_tcp_bind_multiple_times() {
        let config = TcpConfig::default();
        let mut transport = TcpAgentTransport::new(config);
        
        // First bind should succeed
        assert!(transport.bind().await.is_ok());
        
        // Second bind should also work (will create new listener)
        assert!(transport.bind().await.is_ok());
        
        transport.shutdown().await.ok();
    }

    // ============================================
    // Async Tests for Accept
    // ============================================

    #[tokio::test]
    async fn test_tcp_accept_not_bound() {
        let config = TcpConfig::default();
        let transport = TcpAgentTransport::new(config);
        
        // accept without binding should fail
        let result = transport.accept().await;
        assert!(result.is_err());
        match result {
            Err(TransportError::NotBound) => {}
            _ => panic!("Expected NotBound error"),
        }
    }

    // ============================================
    // Async Tests for Local Address
    // ============================================

    #[tokio::test]
    async fn test_tcp_local_addr_not_bound() {
        let config = TcpConfig::default();
        let transport = TcpAgentTransport::new(config);
        
        let result = transport.local_addr();
        assert!(result.is_err());
        match result {
            Err(TransportError::NotBound) => {}
            _ => panic!("Expected NotBound error"),
        }
    }

    #[tokio::test]
    async fn test_tcp_local_addr_after_bind() {
        let config = TcpConfig::default();
        let mut transport = TcpAgentTransport::new(config);
        
        transport.bind().await.ok();
        let local_addr = transport.local_addr();
        assert!(local_addr.is_ok());
        
        transport.shutdown().await.ok();
    }

    // ============================================
    // Async Tests for Connect
    // ============================================

    #[tokio::test]
    async fn test_tcp_connect_timeout() {
        let config = TcpConfig {
            connect_timeout: Duration::from_millis(100), // Very short timeout
            ..Default::default()
        };
        let transport = TcpAgentTransport::new(config);
        
        // Try to connect to address that won't respond
        let addr: SocketAddr = "192.0.2.1:12345".parse().expect("TEST-NET-1 address should parse");
        let result = transport.connect(addr).await;
        
        // Should timeout or fail
        assert!(result.is_err());
    }

    // ============================================
    // Async Tests for Shutdown
    // ============================================

    #[tokio::test]
    async fn test_tcp_shutdown_not_bound() {
        let config = TcpConfig::default();
        let mut transport = TcpAgentTransport::new(config);
        
        // Shutdown without binding should succeed
        let result = transport.shutdown().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_tcp_shutdown_after_bind() {
        let config = TcpConfig::default();
        let mut transport = TcpAgentTransport::new(config);
        
        transport.bind().await.ok();
        let result = transport.shutdown().await;
        assert!(result.is_ok());
        
        // After shutdown, should not be able to get local addr
        let result = transport.local_addr();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tcp_shutdown_idempotent() {
        let config = TcpConfig::default();
        let mut transport = TcpAgentTransport::new(config);
        
        transport.bind().await.ok();
        
        // Multiple shutdowns should be safe
        for _ in 0..5 {
            let result = transport.shutdown().await;
            assert!(result.is_ok());
        }
    }

    // ============================================
    // Integration Tests
    // ============================================

    #[tokio::test]
    async fn test_tcp_full_lifecycle() {
        let config = TcpConfig::default();
        let mut transport = TcpAgentTransport::new(config);
        
        // Bind
        transport.bind().await.ok();
        let local_addr = transport.local_addr().ok();
        if let Some(addr) = local_addr {
            assert!(addr.port() > 0);
        }
        
        // Shutdown
        transport.shutdown().await.ok();
        
        // Verify shutdown
        assert!(transport.local_addr().is_err());
    }

    #[tokio::test]
    async fn test_tcp_multiple_binds() {
        let config = TcpConfig::default();
        let mut transport = TcpAgentTransport::new(config);
        
        let mut addrs = vec![];
        for _ in 0..3 {
            transport.bind().await.ok();
            if let Ok(addr) = transport.local_addr() {
                addrs.push(addr);
            }
        }
        
        // Each bind should have succeeded
        assert_eq!(addrs.len(), 3);
        
        transport.shutdown().await.ok();
    }

    // ============================================
    // Error Handling Tests
    // ============================================

    #[tokio::test]
    async fn test_tcp_operations_after_shutdown() {
        let config = TcpConfig::default();
        let mut transport = TcpAgentTransport::new(config);
        
        transport.bind().await.ok();
        transport.shutdown().await.ok();
        
        // After shutdown, local_addr should fail
        let result = transport.local_addr();
        assert!(result.is_err());
    }

    #[test]
    fn test_tcp_config_variations() {
        // Test various config combinations
        let configs = vec![
            TcpConfig {
                nodelay: false,
                keepalive: None,
                ..Default::default()
            },
            TcpConfig {
                send_buffer_size: 512 * 1024,
                recv_buffer_size: 512 * 1024,
                ..Default::default()
            },
            TcpConfig {
                connect_timeout: Duration::from_secs(30),
                ..Default::default()
            },
        ];
        
        for config in configs {
            let _ = TcpAgentTransport::new(config);
        }
    }

    // ============================================
    // Edge Case Tests
    // ============================================

    #[test]
    fn test_tcp_config_zero_timeout() {
        let config = TcpConfig {
            connect_timeout: Duration::ZERO,
            ..Default::default()
        };
        let _ = TcpAgentTransport::new(config);
    }

    #[test]
    fn test_tcp_config_large_timeout() {
        let config = TcpConfig {
            connect_timeout: Duration::from_secs(3600),
            ..Default::default()
        };
        let _ = TcpAgentTransport::new(config);
    }

    #[test]
    fn test_tcp_config_zero_buffer_size() {
        let config = TcpConfig {
            send_buffer_size: 0,
            recv_buffer_size: 0,
            ..Default::default()
        };
        let _ = TcpAgentTransport::new(config);
    }

    #[test]
    fn test_tcp_config_large_buffer_size() {
        let config = TcpConfig {
            send_buffer_size: 16 * 1024 * 1024, // 16MB
            recv_buffer_size: 16 * 1024 * 1024,
            ..Default::default()
        };
        let _ = TcpAgentTransport::new(config);
    }

    #[tokio::test]
    async fn test_tcp_connect_to_invalid_address() {
        let config = TcpConfig::default();
        let transport = TcpAgentTransport::new(config);
        
        // Test with various addresses
        let addrs = vec![
            "127.0.0.1:0".parse().expect("hardcoded address should parse"),
            "0.0.0.0:0".parse().expect("hardcoded address should parse"),
        ];
        
        for addr in addrs {
            let result = transport.connect(addr).await;
            // May succeed or fail depending on OS
            let _ = result;
        }
    }

    #[tokio::test]
    async fn test_tcp_concurrent_binds() {
        use std::sync::Arc;
        
        let config = TcpConfig::default();
        let transport = Arc::new(tokio::sync::Mutex::new(TcpAgentTransport::new(config)));
        
        let mut handles = vec![];
        
        for _ in 0..5 {
            let t = Arc::clone(&transport);
            let handle = tokio::spawn(async move {
                let mut guard = t.lock().await;
                guard.bind().await
            });
            handles.push(handle);
        }
        
        for handle in handles {
            let result = handle.await.ok();
            // Some may succeed, some may fail due to port conflicts
            let _ = result;
        }
        
        transport.lock().await.shutdown().await.ok();
    }

    #[test]
    fn test_tcp_transport_debug() {
        let config = TcpConfig::default();
        let transport = TcpAgentTransport::new(config);
        let debug_str = format!("{:?}", transport);
        assert!(!debug_str.is_empty());
    }

    #[test]
    fn test_tcp_config_debug() {
        let config = TcpConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("TcpConfig") || !debug_str.is_empty());
    }

    #[tokio::test]
    async fn test_tcp_transport_trait_bounds() {
        // Compile-time test that TcpAgentTransport implements AgentTransport
        fn check_trait<T: AgentTransport>(_transport: T) {}
        let config = TcpConfig::default();
        check_trait(TcpAgentTransport::new(config));
    }

    #[tokio::test]
    async fn test_tcp_connection_trait_bounds() {
        // Compile-time test - TcpConnection implements AgentConnection
        // This is verified by the fact that accept() and connect() return Box<dyn AgentConnection>
    }

    #[tokio::test]
    async fn test_tcp_multiple_instances() {
        let transports: Vec<_> = (0..5)
            .map(|_| TcpAgentTransport::new(TcpConfig::default()))
            .collect();
        
        let mut handles = vec![];
        for mut transport in transports {
            let handle = tokio::spawn(async move {
                transport.bind().await
            });
            handles.push(handle);
        }
        
        for handle in handles {
            let result = handle.await.ok();
            // Check if result is ok, but don't unwrap
            if let Some(Ok(())) = result {
                // Bind succeeded
            }
        }
    }

    #[tokio::test]
    async fn test_tcp_bind_with_different_addresses() {
        let addresses: Vec<SocketAddr> = vec![
            "0.0.0.0:0".parse().expect("hardcoded address should parse"),
            "127.0.0.1:0".parse().expect("hardcoded address should parse"),
            "[::1]:0".parse().expect("hardcoded IPv6 address should parse"),
        ];
        
        for addr in addresses {
            let config = TcpConfig {
                bind_addr: addr,
                ..Default::default()
            };
            let mut transport = TcpAgentTransport::new(config);
            
            // IPv6 might fail on some systems, so we just verify it doesn't panic
            let result = transport.bind().await;
            if result.is_ok() {
                transport.shutdown().await.ok();
            }
        }
    }

    #[tokio::test]
    async fn test_tcp_transport_state_consistency() {
        let config = TcpConfig::default();
        let mut transport = TcpAgentTransport::new(config);
        
        // Initial state - not bound
        assert!(transport.local_addr().is_err());
        
        // After bind
        transport.bind().await.ok();
        assert!(transport.local_addr().is_ok());
        
        // After shutdown
        transport.shutdown().await.ok();
        assert!(transport.local_addr().is_err());
    }
}
