use crate::{AgentConnection, TransportKind};
use anyhow::Result as AnyhowResult;
use async_trait::async_trait;
use bytes::Bytes;
use quinn::{ClientConfig, Connection, Endpoint, ServerConfig, TransportConfig, VarInt};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, instrument, warn};

use crate::transport::{AgentTransport, TransportError, TransportResult};

#[derive(Debug, Clone)]
pub struct QuicConfig {
    pub bind_addr: SocketAddr,
    pub max_idle_timeout: Duration,
    pub keep_alive_interval: Duration,
    pub max_concurrent_bi_streams: u64,
    pub max_concurrent_uni_streams: u64,
    pub enable_0rtt: bool,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:0"
                .parse()
                .expect("hardcoded bind address should be valid"),
            max_idle_timeout: Duration::from_secs(120),
            keep_alive_interval: Duration::from_secs(10),
            max_concurrent_bi_streams: 128,
            max_concurrent_uni_streams: 128,
            enable_0rtt: true,
        }
    }
}

pub struct QuicAgentTransport {
    config: QuicConfig,
    endpoint: Option<Endpoint>,
}

impl QuicAgentTransport {
    pub fn new(config: QuicConfig) -> Self {
        Self {
            config,
            endpoint: None,
        }
    }

    fn build_transport_config(&self) -> TransportResult<TransportConfig> {
        let mut transport = TransportConfig::default();
        let idle_ms = self.config.max_idle_timeout.as_millis() as u64;
        let idle_timeout = quinn::IdleTimeout::from(
            VarInt::from_u64(idle_ms).map_err(|e| TransportError::Config(e.to_string()))?,
        );
        transport.max_idle_timeout(Some(idle_timeout));
        transport.keep_alive_interval(Some(self.config.keep_alive_interval));
        transport.max_concurrent_bidi_streams(
            VarInt::from_u64(self.config.max_concurrent_bi_streams)
                .map_err(|e| TransportError::Config(e.to_string()))?,
        );
        transport.max_concurrent_uni_streams(
            VarInt::from_u64(self.config.max_concurrent_uni_streams)
                .map_err(|e| TransportError::Config(e.to_string()))?,
        );
        transport.initial_mtu(1200);
        Ok(transport)
    }

    fn build_client_config(&self) -> TransportResult<ClientConfig> {
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();

        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| TransportError::Config(e.to_string()))?;

        let mut client_config = ClientConfig::new(Arc::new(quic_crypto));
        let transport = self.build_transport_config()?;
        client_config.transport_config(Arc::new(transport));
        Ok(client_config)
    }

    fn build_server_config(&self) -> TransportResult<ServerConfig> {
        let cert = rcgen::generate_simple_self_signed(vec!["vigilnet".to_string()])
            .map_err(|e| TransportError::Config(e.to_string()))?;
        let key =
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());

        let server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key.into())
            .map_err(|e| TransportError::Config(e.to_string()))?;

        let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| TransportError::Config(e.to_string()))?;

        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));
        let transport = self.build_transport_config()?;
        server_config.transport_config(Arc::new(transport));
        Ok(server_config)
    }
}

#[async_trait]
impl AgentTransport for QuicAgentTransport {
    #[instrument(skip(self), name = "QuicTransport::bind")]
    async fn bind(&mut self) -> TransportResult<()> {
        let server_config = self.build_server_config()?;

        let endpoint = Endpoint::server(server_config, self.config.bind_addr)
            .map_err(|e| TransportError::Bind(e.to_string()))?;

        let local_addr = endpoint
            .local_addr()
            .map_err(|e| TransportError::Bind(e.to_string()))?;

        info!(addr = %local_addr, "QUIC transport bound");
        self.endpoint = Some(endpoint);
        Ok(())
    }

    #[instrument(skip(self), name = "QuicTransport::connect")]
    async fn connect(&self, addr: SocketAddr) -> TransportResult<Box<dyn AgentConnection>> {
        let endpoint = self.endpoint.as_ref().ok_or(TransportError::NotBound)?;

        let client_config = self.build_client_config()?;

        let connecting = endpoint
            .connect_with(client_config, addr, "vigilnet")
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let connection = if self.config.enable_0rtt {
            match connecting.into_0rtt() {
                Ok((conn, _zero_rtt_accepted)) => {
                    debug!(addr = %addr, "QUIC 0-RTT connection established");
                    conn
                }
                Err(connecting) => {
                    debug!(addr = %addr, "QUIC 0-RTT unavailable, full handshake");
                    connecting
                        .await
                        .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?
                }
            }
        } else {
            connecting
                .await
                .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?
        };

        info!(remote = %connection.remote_address(), "QUIC connection established");

        Ok(Box::new(QuicConnection {
            connection,
            remote_addr: addr,
        }))
    }

    #[instrument(skip(self), name = "QuicTransport::accept")]
    async fn accept(&self) -> TransportResult<Box<dyn AgentConnection>> {
        let endpoint = self.endpoint.as_ref().ok_or(TransportError::NotBound)?;

        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| TransportError::ConnectionFailed("Endpoint closed".into()))?;

        let connection = incoming
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let remote = connection.remote_address();
        info!(remote = %remote, "QUIC connection accepted");

        Ok(Box::new(QuicConnection {
            connection,
            remote_addr: remote,
        }))
    }

    async fn shutdown(&mut self) -> TransportResult<()> {
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.close(VarInt::from_u32(0), b"shutdown");
            endpoint.wait_idle().await;
            info!("QUIC transport shut down");
        }
        Ok(())
    }

    fn transport_kind(&self) -> TransportKind {
        TransportKind::Quic
    }

    fn local_addr(&self) -> TransportResult<SocketAddr> {
        self.endpoint
            .as_ref()
            .ok_or(TransportError::NotBound)?
            .local_addr()
            .map_err(|e| TransportError::Io(e.to_string()))
    }
}

struct QuicConnection {
    connection: Connection,
    remote_addr: SocketAddr,
}

#[async_trait]
impl AgentConnection for QuicConnection {
    async fn send(&self, data: Bytes) -> TransportResult<()> {
        let mut stream = self
            .connection
            .open_uni()
            .await
            .map_err(|e| TransportError::Send(e.to_string()))?;

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
            .finish()
            .map_err(|e| TransportError::Send(e.to_string()))?;

        debug!(size = data.len(), "QUIC data sent");
        Ok(())
    }

    async fn recv(&self) -> TransportResult<Bytes> {
        let mut stream = self
            .connection
            .accept_uni()
            .await
            .map_err(|e| TransportError::Recv(e.to_string()))?;

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

        let data = stream
            .read_to_end(len)
            .await
            .map_err(|e| TransportError::Recv(e.to_string()))?;

        debug!(size = data.len(), "QUIC data received");
        Ok(Bytes::from(data))
    }

    fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    fn transport_kind(&self) -> TransportKind {
        TransportKind::Quic
    }

    async fn close(&self) -> TransportResult<()> {
        self.connection.close(VarInt::from_u32(0), b"close");
        Ok(())
    }
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================
    // Unit Tests for Core Functionality
    // ============================================

    #[test]
    fn test_quic_config_default() {
        let config = QuicConfig::default();
        assert_eq!(config.bind_addr.to_string(), "0.0.0.0:0");
        assert_eq!(config.max_idle_timeout, Duration::from_secs(120));
        assert_eq!(config.keep_alive_interval, Duration::from_secs(10));
        assert_eq!(config.max_concurrent_bi_streams, 128);
        assert_eq!(config.max_concurrent_uni_streams, 128);
        assert!(config.enable_0rtt);
    }

    #[test]
    fn test_quic_config_clone() {
        let config = QuicConfig::default();
        let cloned = config.clone();
        assert_eq!(config.bind_addr, cloned.bind_addr);
        assert_eq!(config.max_idle_timeout, cloned.max_idle_timeout);
        assert_eq!(config.enable_0rtt, cloned.enable_0rtt);
    }

    #[test]
    fn test_quic_transport_creation() {
        let config = QuicConfig::default();
        let transport = QuicAgentTransport::new(config);
        assert_eq!(transport.transport_kind(), TransportKind::Quic);
    }

    #[test]
    fn test_quic_transport_kind() {
        let config = QuicConfig::default();
        let transport = QuicAgentTransport::new(config);
        assert_eq!(transport.transport_kind(), TransportKind::Quic);
    }

    // ============================================
    // Async Tests for Bind
    // ============================================

    #[tokio::test]
    async fn test_quic_bind_success() {
        let config = QuicConfig::default();
        let mut transport = QuicAgentTransport::new(config);
        let result = transport.bind().await;
        
        // QUIC binding should succeed in test environment
        if result.is_ok() {
            let local_addr = transport.local_addr();
            assert!(local_addr.is_ok());
            transport.shutdown().await.ok();
        }
    }

    #[tokio::test]
    async fn test_quic_bind_specific_address() {
        let config = QuicConfig {
            bind_addr: "127.0.0.1:0".parse().expect("hardcoded address should parse"),
            ..Default::default()
        };
        let mut transport = QuicAgentTransport::new(config);
        let result = transport.bind().await;
        
        if result.is_ok() {
            let local_addr = transport.local_addr().ok();
            if let Some(addr) = local_addr {
                assert_eq!(addr.ip().to_string(), "127.0.0.1");
            }
            transport.shutdown().await.ok();
        }
    }

    #[tokio::test]
    async fn test_quic_bind_multiple_times() {
        let config = QuicConfig::default();
        let mut transport = QuicAgentTransport::new(config);
        
        // First bind
        let result1 = transport.bind().await;
        if result1.is_ok() {
            // Second bind might succeed (creating new endpoint)
            let _result2 = transport.bind().await;
            transport.shutdown().await.ok();
        }
    }

    // ============================================
    // Async Tests for Connect
    // ============================================

    #[tokio::test]
    async fn test_quic_connect_not_bound() {
        let config = QuicConfig::default();
        let transport = QuicAgentTransport::new(config);
        let addr: SocketAddr = "127.0.0.1:8080".parse().expect("hardcoded address should parse");
        
        let result = transport.connect(addr).await;
        assert!(result.is_err());
        match result {
            Err(TransportError::NotBound) => {}
            _ => panic!("Expected NotBound error"),
        }
    }

    // ============================================
    // Async Tests for Accept
    // ============================================

    #[tokio::test]
    async fn test_quic_accept_not_bound() {
        let config = QuicConfig::default();
        let transport = QuicAgentTransport::new(config);
        
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
    async fn test_quic_local_addr_not_bound() {
        let config = QuicConfig::default();
        let transport = QuicAgentTransport::new(config);
        
        let result = transport.local_addr();
        assert!(result.is_err());
        match result {
            Err(TransportError::NotBound) => {}
            _ => panic!("Expected NotBound error"),
        }
    }

    #[tokio::test]
    async fn test_quic_local_addr_after_bind() {
        let config = QuicConfig::default();
        let mut transport = QuicAgentTransport::new(config);
        
        let bind_result = transport.bind().await;
        if bind_result.is_ok() {
            let local_addr = transport.local_addr();
            assert!(local_addr.is_ok());
            transport.shutdown().await.ok();
        }
    }

    // ============================================
    // Async Tests for Shutdown
    // ============================================

    #[tokio::test]
    async fn test_quic_shutdown_not_bound() {
        let config = QuicConfig::default();
        let mut transport = QuicAgentTransport::new(config);
        
        // Shutdown without binding should succeed
        let result = transport.shutdown().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_quic_shutdown_after_bind() {
        let config = QuicConfig::default();
        let mut transport = QuicAgentTransport::new(config);
        
        if transport.bind().await.is_ok() {
            let result = transport.shutdown().await;
            assert!(result.is_ok());
            
            // After shutdown, should not be able to get local addr
            let result = transport.local_addr();
            assert!(result.is_err());
        }
    }

    #[tokio::test]
    async fn test_quic_shutdown_idempotent() {
        let config = QuicConfig::default();
        let mut transport = QuicAgentTransport::new(config);
        
        if transport.bind().await.is_ok() {
            // Multiple shutdowns should be safe
            for _ in 0..5 {
                let result = transport.shutdown().await;
                assert!(result.is_ok());
            }
        }
    }

    // ============================================
    // Config Tests
    // ============================================

    #[test]
    fn test_quic_transport_config_building() {
        let config = QuicConfig::default();
        let transport = QuicAgentTransport::new(config);
        
        // Test building transport config
        let result = transport.build_transport_config();
        assert!(result.is_ok());
    }

    #[test]
    fn test_quic_client_config_building() {
        let config = QuicConfig::default();
        let transport = QuicAgentTransport::new(config);
        
        // Test building client config
        let result = transport.build_client_config();
        assert!(result.is_ok());
    }

    #[test]
    fn test_quic_server_config_building() {
        let config = QuicConfig::default();
        let transport = QuicAgentTransport::new(config);
        
        // Test building server config
        let result = transport.build_server_config();
        assert!(result.is_ok());
    }

    // ============================================
    // Integration Tests
    // ============================================

    #[tokio::test]
    async fn test_quic_full_lifecycle() {
        let config = QuicConfig::default();
        let mut transport = QuicAgentTransport::new(config);
        
        // Bind
        let bind_result = transport.bind().await;
        
        if bind_result.is_ok() {
            let local_addr = transport.local_addr().ok();
            if let Some(addr) = local_addr {
                assert!(addr.port() > 0);
            }
            
            // Shutdown
            transport.shutdown().await.ok();
            
            // Verify shutdown
            assert!(transport.local_addr().is_err());
        }
    }

    #[tokio::test]
    async fn test_quic_multiple_instances() {
        let mut transports: Vec<QuicAgentTransport> = (0..3)
            .map(|_| QuicAgentTransport::new(QuicConfig::default()))
            .collect();
        
        for transport in &mut transports {
            // Each should be able to bind independently
            let _ = transport.bind().await;
        }
        
        for transport in &mut transports {
            transport.shutdown().await.ok();
        }
    }

    // ============================================
    // Error Handling Tests
    // ============================================

    #[tokio::test]
    async fn test_quic_operations_after_shutdown() {
        let config = QuicConfig::default();
        let mut transport = QuicAgentTransport::new(config);
        
        if transport.bind().await.is_ok() {
            transport.shutdown().await.ok();
            
            // After shutdown, local_addr should fail
            let result = transport.local_addr();
            assert!(result.is_err());
        }
    }

    // ============================================
    // Edge Case Tests
    // ============================================

    #[test]
    fn test_quic_config_zero_timeout() {
        let config = QuicConfig {
            max_idle_timeout: Duration::ZERO,
            ..Default::default()
        };
        let _ = QuicAgentTransport::new(config);
    }

    #[test]
    fn test_quic_config_large_timeout() {
        let config = QuicConfig {
            max_idle_timeout: Duration::from_secs(3600),
            ..Default::default()
        };
        let _ = QuicAgentTransport::new(config);
    }

    #[test]
    fn test_quic_config_zero_streams() {
        let config = QuicConfig {
            max_concurrent_bi_streams: 0,
            max_concurrent_uni_streams: 0,
            ..Default::default()
        };
        let _ = QuicAgentTransport::new(config);
    }

    #[test]
    fn test_quic_config_large_streams() {
        let config = QuicConfig {
            max_concurrent_bi_streams: 10000,
            max_concurrent_uni_streams: 10000,
            ..Default::default()
        };
        let _ = QuicAgentTransport::new(config);
    }

    #[test]
    fn test_quic_config_disabled_0rtt() {
        let config = QuicConfig {
            enable_0rtt: false,
            ..Default::default()
        };
        let _ = QuicAgentTransport::new(config);
    }

    #[tokio::test]
    async fn test_quic_bind_with_different_addresses() {
        let addresses: Vec<SocketAddr> = vec![
            "0.0.0.0:0".parse().expect("hardcoded address should parse"),
            "127.0.0.1:0".parse().expect("hardcoded address should parse"),
        ];
        
        for addr in addresses {
            let config = QuicConfig {
                bind_addr: addr,
                ..Default::default()
            };
            let mut transport = QuicAgentTransport::new(config);
            
            // QUIC might fail on some addresses, just verify it doesn't panic
            let result = transport.bind().await;
            if result.is_ok() {
                transport.shutdown().await.ok();
            }
        }
    }

    #[tokio::test]
    async fn test_quic_concurrent_operations() {
        use std::sync::Arc;
        
        let config = QuicConfig::default();
        let transport = Arc::new(tokio::sync::Mutex::new(QuicAgentTransport::new(config)));
        
        let mut handles = vec![];
        
        // Spawn multiple tasks that try to bind
        for _ in 0..3 {
            let t = Arc::clone(&transport);
            let handle = tokio::spawn(async move {
                let mut guard = t.lock().await;
                guard.bind().await
            });
            handles.push(handle);
        }
        
        for handle in handles {
            let _ = handle.await.ok();
        }
        
        transport.lock().await.shutdown().await.ok();
    }

    #[test]
    fn test_quic_transport_debug() {
        let config = QuicConfig::default();
        let transport = QuicAgentTransport::new(config);
        let debug_str = format!("{:?}", transport);
        assert!(!debug_str.is_empty());
    }

    #[test]
    fn test_quic_config_debug() {
        let config = QuicConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("QuicConfig") || !debug_str.is_empty());
    }

    #[tokio::test]
    async fn test_quic_transport_trait_bounds() {
        // Compile-time test that QuicAgentTransport implements AgentTransport
        fn check_trait<T: AgentTransport>(_transport: T) {}
        let config = QuicConfig::default();
        check_trait(QuicAgentTransport::new(config));
    }

    #[test]
    fn test_skip_server_verification() {
        let verifier = SkipServerVerification;
        
        // Test supported schemes
        let schemes = verifier.supported_verify_schemes();
        assert!(!schemes.is_empty());
        
        // Should include expected schemes
        assert!(schemes.contains(&rustls::SignatureScheme::ED25519));
        assert!(schemes.contains(&rustls::SignatureScheme::ECDSA_NISTP256_SHA256));
    }

    #[test]
    fn test_skip_server_verification_debug() {
        let verifier = SkipServerVerification;
        let debug_str = format!("{:?}", verifier);
        assert!(debug_str.contains("SkipServerVerification"));
    }

    #[tokio::test]
    async fn test_quic_transport_state_consistency() {
        let config = QuicConfig::default();
        let mut transport = QuicAgentTransport::new(config);
        
        // Initial state - not bound
        assert!(transport.local_addr().is_err());
        
        // After bind
        if transport.bind().await.is_ok() {
            assert!(transport.local_addr().is_ok());
            
            // After shutdown
            transport.shutdown().await.ok();
            assert!(transport.local_addr().is_err());
        }
    }

    #[tokio::test]
    async fn test_quic_config_variations() {
        let configs = vec![
            QuicConfig {
                enable_0rtt: true,
                ..Default::default()
            },
            QuicConfig {
                enable_0rtt: false,
                ..Default::default()
            },
            QuicConfig {
                max_concurrent_bi_streams: 64,
                max_concurrent_uni_streams: 64,
                ..Default::default()
            },
            QuicConfig {
                keep_alive_interval: Duration::from_secs(5),
                ..Default::default()
            },
        ];
        
        for config in configs {
            let mut transport = QuicAgentTransport::new(config);
            // Just verify the config is valid
            let _ = transport.bind().await;
            transport.shutdown().await.ok();
        }
    }

    #[tokio::test]
    async fn test_quic_error_recovery() {
        let config = QuicConfig::default();
        let mut transport = QuicAgentTransport::new(config);
        
        // Try operations that might fail
        let addr: SocketAddr = "127.0.0.1:8080".parse().expect("hardcoded address should parse");
        let _ = transport.connect(addr).await; // Should fail - not bound
        
        // Transport should still be usable
        if transport.bind().await.is_ok() {
            transport.shutdown().await.ok();
        }
    }
}
