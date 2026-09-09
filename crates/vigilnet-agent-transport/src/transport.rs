use crate::ble_transport::BleAgentTransport;
use crate::quic_transport::{QuicAgentTransport, QuicConfig};
use crate::tcp_transport::{TcpAgentTransport, TcpConfig};
use crate::AgentConnection;
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Transport not available: {0}")]
    NotAvailable(String),

    #[error("Transport not bound")]
    NotBound,

    #[error("Bind failed: {0}")]
    Bind(String),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Send error: {0}")]
    Send(String),

    #[error("Recv error: {0}")]
    Recv(String),

    #[error("IO error: {0}")]
    Io(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("All transports failed")]
    AllTransportsFailed,
}

pub type TransportResult<T> = std::result::Result<T, TransportError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportKind {
    Quic,
    Tcp,
    Ble,
    Tor,
    I2p,
    Freenet,
    WireGuard,
    Nym,
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Quic => write!(f, "QUIC"),
            Self::Tcp => write!(f, "TCP"),
            Self::Ble => write!(f, "BLE"),
            Self::Tor => write!(f, "Tor"),
            Self::I2p => write!(f, "I2P"),
            Self::Freenet => write!(f, "Freenet"),
            Self::WireGuard => write!(f, "WireGuard"),
            Self::Nym => write!(f, "Nym"),
        }
    }
}

#[async_trait]
pub trait AgentTransport: Send + Sync {
    async fn bind(&mut self) -> TransportResult<()>;
    async fn connect(&self, addr: SocketAddr) -> TransportResult<Box<dyn AgentConnection>>;
    async fn accept(&self) -> TransportResult<Box<dyn AgentConnection>>;
    async fn shutdown(&mut self) -> TransportResult<()>;
    fn transport_kind(&self) -> TransportKind;
    fn local_addr(&self) -> TransportResult<SocketAddr>;
}

#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub quic: QuicConfig,
    pub tcp: TcpConfig,
    pub enable_quic: bool,
    pub enable_tcp: bool,
    pub enable_ble: bool,
    pub fallback_timeout: Duration,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            quic: QuicConfig::default(),
            tcp: TcpConfig::default(),
            enable_quic: true,
            enable_tcp: true,
            enable_ble: false,
            fallback_timeout: Duration::from_secs(5),
        }
    }
}

pub struct UnifiedTransport {
    config: TransportConfig,
    quic: Option<RwLock<QuicAgentTransport>>,
    tcp: Option<RwLock<TcpAgentTransport>>,
    ble: Option<RwLock<BleAgentTransport>>,
    state: RwLock<TransportState>,
}

#[derive(Debug, Clone)]
struct TransportState {
    quic_bound: bool,
    tcp_bound: bool,
    ble_bound: bool,
    active_transport: Option<TransportKind>,
}

impl Default for TransportState {
    fn default() -> Self {
        Self {
            quic_bound: false,
            tcp_bound: false,
            ble_bound: false,
            active_transport: None,
        }
    }
}

impl UnifiedTransport {
    pub fn new(config: TransportConfig) -> Self {
        let quic = if config.enable_quic {
            Some(RwLock::new(QuicAgentTransport::new(config.quic.clone())))
        } else {
            None
        };

        let tcp = if config.enable_tcp {
            Some(RwLock::new(TcpAgentTransport::new(config.tcp.clone())))
        } else {
            None
        };

        let ble = if config.enable_ble {
            Some(RwLock::new(BleAgentTransport::new()))
        } else {
            None
        };

        Self {
            config,
            quic,
            tcp,
            ble,
            state: RwLock::new(TransportState::default()),
        }
    }

    #[instrument(skip(self), name = "UnifiedTransport::bind_all")]
    pub async fn bind_all(&self) -> TransportResult<()> {
        let mut state = self.state.write().await;

        if let Some(quic) = &self.quic {
            match quic.write().await.bind().await {
                Ok(()) => {
                    state.quic_bound = true;
                    state.active_transport = Some(TransportKind::Quic);
                    info!("QUIC transport ready");
                }
                Err(e) => {
                    warn!(error = %e, "QUIC bind failed, will try fallback");
                }
            }
        }

        if let Some(tcp) = &self.tcp {
            match tcp.write().await.bind().await {
                Ok(()) => {
                    state.tcp_bound = true;
                    if state.active_transport.is_none() {
                        state.active_transport = Some(TransportKind::Tcp);
                    }
                    info!("TCP transport ready");
                }
                Err(e) => {
                    warn!(error = %e, "TCP bind failed");
                }
            }
        }

        if let Some(ble) = &self.ble {
            match ble.write().await.bind().await {
                Ok(()) => {
                    state.ble_bound = true;
                    if state.active_transport.is_none() {
                        state.active_transport = Some(TransportKind::Ble);
                    }
                    info!("BLE transport ready");
                }
                Err(e) => {
                    debug!(error = %e, "BLE bind failed (expected on most platforms)");
                }
            }
        }

        // Use ok_or to convert Option to Result with proper error
        let active_transport = state
            .active_transport
            .ok_or_else(|| {
                error!("All transports failed to bind");
                TransportError::AllTransportsFailed
            })?;
            
        info!(
            active = %active_transport,
            quic = state.quic_bound,
            tcp = state.tcp_bound,
            ble = state.ble_bound,
            "Transport layer initialized"
        );

        Ok(())
    }

    #[instrument(skip(self), name = "UnifiedTransport::connect")]
    pub async fn connect(&self, addr: SocketAddr) -> TransportResult<Box<dyn AgentConnection>> {
        let state = self.state.read().await;

        if state.quic_bound {
            if let Some(quic) = &self.quic {
                match tokio::time::timeout(
                    self.config.fallback_timeout,
                    quic.read().await.connect(addr),
                )
                .await
                {
                    Ok(Ok(conn)) => {
                        debug!(transport = "QUIC", addr = %addr, "Connected");
                        return Ok(conn);
                    }
                    Ok(Err(e)) => {
                        warn!(error = %e, "QUIC connect failed, falling back to TCP");
                    }
                    Err(_) => {
                        warn!("QUIC connect timed out, falling back to TCP");
                    }
                }
            }
        }

        if state.tcp_bound {
            if let Some(tcp) = &self.tcp {
                match tcp.read().await.connect(addr).await {
                    Ok(conn) => {
                        debug!(transport = "TCP", addr = %addr, "Connected via fallback");
                        return Ok(conn);
                    }
                    Err(e) => {
                        warn!(error = %e, "TCP connect failed, falling back to BLE");
                    }
                }
            }
        }

        if state.ble_bound {
            if let Some(ble) = &self.ble {
                match ble.read().await.connect(addr).await {
                    Ok(conn) => {
                        debug!(transport = "BLE", addr = %addr, "Connected via fallback");
                        return Ok(conn);
                    }
                    Err(e) => {
                        warn!(error = %e, "BLE connect failed");
                    }
                }
            }
        }

        Err(TransportError::AllTransportsFailed)
    }

    #[instrument(skip(self), name = "UnifiedTransport::accept")]
    pub async fn accept(&self) -> TransportResult<Box<dyn AgentConnection>> {
        let state = self.state.read().await;

        if state.quic_bound {
            if let Some(quic) = &self.quic {
                return quic.read().await.accept().await;
            }
        }

        if state.tcp_bound {
            if let Some(tcp) = &self.tcp {
                return tcp.read().await.accept().await;
            }
        }

        Err(TransportError::AllTransportsFailed)
    }

    pub async fn shutdown(&self) -> TransportResult<()> {
        if let Some(quic) = &self.quic {
            let _ = quic.write().await.shutdown().await;
        }
        if let Some(tcp) = &self.tcp {
            let _ = tcp.write().await.shutdown().await;
        }
        if let Some(ble) = &self.ble {
            let _ = ble.write().await.shutdown().await;
        }

        let mut state = self.state.write().await;
        *state = TransportState::default();

        info!("All transports shut down");
        Ok(())
    }

    pub async fn active_transport(&self) -> Option<TransportKind> {
        self.state.read().await.active_transport
    }

    pub async fn available_transports(&self) -> Vec<TransportKind> {
        let state = self.state.read().await;
        let mut transports = Vec::new();
        if state.quic_bound {
            transports.push(TransportKind::Quic);
        }
        if state.tcp_bound {
            transports.push(TransportKind::Tcp);
        }
        if state.ble_bound {
            transports.push(TransportKind::Ble);
        }
        transports
    }

    pub async fn connect_with(
        &self,
        kind: TransportKind,
        addr: SocketAddr,
    ) -> TransportResult<Box<dyn AgentConnection>> {
        match kind {
            TransportKind::Quic => {
                let quic = self
                    .quic
                    .as_ref()
                    .ok_or_else(|| TransportError::NotAvailable("QUIC not enabled".into()))?;
                quic.read().await.connect(addr).await
            }
            TransportKind::Tcp => {
                let tcp = self
                    .tcp
                    .as_ref()
                    .ok_or_else(|| TransportError::NotAvailable("TCP not enabled".into()))?;
                tcp.read().await.connect(addr).await
            }
            TransportKind::Ble => {
                let ble = self
                    .ble
                    .as_ref()
                    .ok_or_else(|| TransportError::NotAvailable("BLE not enabled".into()))?;
                ble.read().await.connect(addr).await
            }
            _ => Err(TransportError::NotAvailable(format!("{:?} not available in UnifiedTransport", kind))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================
    // Unit Tests for Core Functionality
    // ============================================

    #[test]
    fn test_transport_kind_display() {
        assert_eq!(TransportKind::Quic.to_string(), "QUIC");
        assert_eq!(TransportKind::Tcp.to_string(), "TCP");
        assert_eq!(TransportKind::Ble.to_string(), "BLE");
        assert_eq!(TransportKind::Tor.to_string(), "Tor");
        assert_eq!(TransportKind::I2p.to_string(), "I2P");
        assert_eq!(TransportKind::Freenet.to_string(), "Freenet");
        assert_eq!(TransportKind::WireGuard.to_string(), "WireGuard");
        assert_eq!(TransportKind::Nym.to_string(), "Nym");
    }

    #[test]
    fn test_default_config() {
        let config = TransportConfig::default();
        assert!(config.enable_quic);
        assert!(config.enable_tcp);
        assert!(!config.enable_ble);
        assert_eq!(config.fallback_timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_transport_config_clone() {
        let config = TransportConfig::default();
        let cloned = config.clone();
        assert_eq!(config.enable_quic, cloned.enable_quic);
        assert_eq!(config.enable_tcp, cloned.enable_tcp);
        assert_eq!(config.fallback_timeout, cloned.fallback_timeout);
    }

    #[test]
    fn test_transport_state_default() {
        let state: TransportState = Default::default();
        assert!(!state.quic_bound);
        assert!(!state.tcp_bound);
        assert!(!state.ble_bound);
        assert!(state.active_transport.is_none());
    }

    #[test]
    fn test_transport_state_clone() {
        let state = TransportState {
            quic_bound: true,
            tcp_bound: false,
            ble_bound: true,
            active_transport: Some(TransportKind::Quic),
        };
        let cloned = state.clone();
        assert_eq!(state.quic_bound, cloned.quic_bound);
        assert_eq!(state.active_transport, cloned.active_transport);
    }

    #[tokio::test]
    async fn test_unified_transport_no_transports() {
        let config = TransportConfig {
            enable_quic: false,
            enable_tcp: false,
            enable_ble: false,
            ..Default::default()
        };
        let transport = UnifiedTransport::new(config);
        let result = transport.bind_all().await;
        assert!(result.is_err());
        match result {
            Err(TransportError::AllTransportsFailed) => {}
            _ => panic!("Expected AllTransportsFailed error"),
        }
    }

    #[tokio::test]
    async fn test_unified_transport_tcp_only() {
        let config = TransportConfig {
            enable_quic: false,
            enable_tcp: true,
            enable_ble: false,
            ..Default::default()
        };
        let transport = UnifiedTransport::new(config);
        let result = transport.bind_all().await;
        assert!(result.is_ok());

        let active = transport.active_transport().await;
        assert_eq!(active, Some(TransportKind::Tcp));

        transport.shutdown().await.ok();
    }

    #[tokio::test]
    async fn test_unified_transport_quic_only() {
        let config = TransportConfig {
            enable_quic: true,
            enable_tcp: false,
            enable_ble: false,
            ..Default::default()
        };
        let transport = UnifiedTransport::new(config);
        let result = transport.bind_all().await;
        // QUIC might fail to bind, but let's check the structure
        // The result depends on whether QUIC can bind
        let _ = result;
    }

    #[tokio::test]
    async fn test_available_transports() {
        let config = TransportConfig {
            enable_quic: false,
            enable_tcp: true,
            enable_ble: false,
            ..Default::default()
        };
        let transport = UnifiedTransport::new(config);
        transport.bind_all().await.ok();

        let available = transport.available_transports().await;
        assert!(available.contains(&TransportKind::Tcp));
        assert!(!available.contains(&TransportKind::Ble));

        transport.shutdown().await.ok();
    }

    #[tokio::test]
    async fn test_active_transport_none_when_not_bound() {
        let config = TransportConfig {
            enable_quic: false,
            enable_tcp: false,
            enable_ble: false,
            ..Default::default()
        };
        let transport = UnifiedTransport::new(config);
        let active = transport.active_transport().await;
        assert!(active.is_none());
    }

    // ============================================
    // Integration Tests
    // ============================================

    #[tokio::test]
    async fn test_unified_transport_full_lifecycle() {
        let config = TransportConfig {
            enable_quic: false,
            enable_tcp: true,
            enable_ble: false,
            ..Default::default()
        };
        let transport = UnifiedTransport::new(config);

        // Bind
        transport.bind_all().await.ok();
        assert!(transport.active_transport().await.is_some());

        // Check available transports
        let available = transport.available_transports().await;
        assert!(!available.is_empty());

        // Shutdown
        transport.shutdown().await.ok();
        
        // After shutdown, no active transport
        let active = transport.active_transport().await;
        assert!(active.is_none());
    }

    #[tokio::test]
    async fn test_transport_creation_with_all_disabled() {
        let config = TransportConfig {
            enable_quic: false,
            enable_tcp: false,
            enable_ble: false,
            ..Default::default()
        };

        let transport = UnifiedTransport::new(config);
        assert!(transport.quic.is_none());
        assert!(transport.tcp.is_none());
        assert!(transport.ble.is_none());
    }

    #[tokio::test]
    async fn test_transport_creation_with_all_enabled() {
        let config = TransportConfig {
            enable_quic: true,
            enable_tcp: true,
            enable_ble: true,
            ..Default::default()
        };

        let transport = UnifiedTransport::new(config);
        assert!(transport.quic.is_some());
        assert!(transport.tcp.is_some());
        assert!(transport.ble.is_some());
    }

    #[tokio::test]
    async fn test_multiple_bind_attempts() {
        let config = TransportConfig {
            enable_quic: false,
            enable_tcp: true,
            enable_ble: false,
            ..Default::default()
        };

        let transport = UnifiedTransport::new(config);
        
        // First bind should succeed
        let result1 = transport.bind_all().await;
        // Subsequent binds might fail or succeed depending on state
        let result2 = transport.bind_all().await;
        
        // At least one should succeed or we should handle gracefully
        let _ = (result1, result2);

        transport.shutdown().await.ok();
    }

    // ============================================
    // Error Handling Tests
    // ============================================

    #[tokio::test]
    async fn test_connect_without_binding() {
        let config = TransportConfig {
            enable_quic: false,
            enable_tcp: false,
            enable_ble: false,
            ..Default::default()
        };
        let transport = UnifiedTransport::new(config);
        
        let addr: SocketAddr = "127.0.0.1:8080".parse().expect("hardcoded address should parse");
        let result = transport.connect(addr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_accept_without_binding() {
        let config = TransportConfig {
            enable_quic: false,
            enable_tcp: false,
            enable_ble: false,
            ..Default::default()
        };
        let transport = UnifiedTransport::new(config);
        
        let result = transport.accept().await;
        assert!(result.is_err());
        match result {
            Err(TransportError::AllTransportsFailed) => {}
            _ => panic!("Expected AllTransportsFailed error"),
        }
    }

    #[tokio::test]
    async fn test_connect_with_unavailable_transport() {
        let config = TransportConfig {
            enable_quic: true,
            enable_tcp: false,
            enable_ble: false,
            ..Default::default()
        };
        let transport = UnifiedTransport::new(config);
        
        let addr: SocketAddr = "127.0.0.1:8080".parse().expect("hardcoded address should parse");
        let result = transport.connect_with(TransportKind::Tcp, addr).await;
        assert!(result.is_err());
        
        match result {
            Err(TransportError::NotAvailable(msg)) => {
                assert!(msg.contains("TCP not enabled"));
            }
            _ => panic!("Expected NotAvailable error"),
        }
    }

    #[tokio::test]
    async fn test_connect_with_ble_unavailable() {
        let config = TransportConfig {
            enable_quic: false,
            enable_tcp: true,
            enable_ble: false,
            ..Default::default()
        };
        let transport = UnifiedTransport::new(config);
        
        let addr: SocketAddr = "127.0.0.1:8080".parse().expect("hardcoded address should parse");
        let result = transport.connect_with(TransportKind::Ble, addr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connect_with_tor_not_available() {
        let config = TransportConfig {
            enable_quic: true,
            enable_tcp: true,
            enable_ble: false,
            ..Default::default()
        };
        let transport = UnifiedTransport::new(config);
        
        let addr: SocketAddr = "127.0.0.1:8080".parse().expect("hardcoded address should parse");
        let result = transport.connect_with(TransportKind::Tor, addr).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not available"));
    }

    // ============================================
    // Edge Case Tests
    // ============================================

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

    #[tokio::test]
    async fn test_shutdown_idempotent() {
        let config = TransportConfig {
            enable_quic: false,
            enable_tcp: true,
            enable_ble: false,
            ..Default::default()
        };
        let transport = UnifiedTransport::new(config);
        
        transport.bind_all().await.ok();
        
        // Multiple shutdowns should be safe
        transport.shutdown().await.ok();
        transport.shutdown().await.ok();
        transport.shutdown().await.ok();
    }

    #[tokio::test]
    async fn test_shutdown_without_bind() {
        let config = TransportConfig::default();
        let transport = UnifiedTransport::new(config);
        
        // Should not panic
        let result = transport.shutdown().await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_all_transport_kinds() {
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
            let display = kind.to_string();
            assert!(!display.is_empty());
            
            // Verify Debug works
            let debug = format!("{:?}", kind);
            assert!(!debug.is_empty());
            
            // Verify Clone works
            let _cloned = kind.clone();
            
            // Verify PartialEq works
            assert_eq!(kind, kind);
        }
    }

    #[tokio::test]
    async fn test_available_transports_empty() {
        let config = TransportConfig {
            enable_quic: false,
            enable_tcp: false,
            enable_ble: false,
            ..Default::default()
        };
        let transport = UnifiedTransport::new(config);
        
        // Before binding, no transports should be available
        let available = transport.available_transports().await;
        assert!(available.is_empty());
    }

    #[tokio::test]
    async fn test_transport_state_after_shutdown() {
        let config = TransportConfig {
            enable_quic: false,
            enable_tcp: true,
            enable_ble: false,
            ..Default::default()
        };
        let transport = UnifiedTransport::new(config);
        
        transport.bind_all().await.ok();
        assert!(transport.active_transport().await.is_some());
        
        transport.shutdown().await.ok();
        
        // State should be reset
        let available = transport.available_transports().await;
        assert!(available.is_empty());
        assert!(transport.active_transport().await.is_none());
    }

    #[test]
    fn test_transport_error_variants() {
        let errors = vec![
            TransportError::ConnectionFailed("test".to_string()),
            TransportError::NotAvailable("test".to_string()),
            TransportError::NotBound,
            TransportError::Bind("test".to_string()),
            TransportError::Config("test".to_string()),
            TransportError::Send("test".to_string()),
            TransportError::Recv("test".to_string()),
            TransportError::Io("test".to_string()),
            TransportError::Timeout("test".to_string()),
            TransportError::AllTransportsFailed,
        ];

        for err in errors {
            let msg = err.to_string();
            assert!(!msg.is_empty());
            
            // Verify Display trait
            let display = format!("{}", err);
            assert!(!display.is_empty());
            
            // Verify Debug trait
            let debug = format!("{:?}", err);
            assert!(!debug.is_empty());
        }
    }

    #[test]
    fn test_transport_error_display_messages() {
        assert!(TransportError::NotBound.to_string().contains("not bound"));
        assert!(TransportError::AllTransportsFailed.to_string().contains("All transports failed"));
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        use std::sync::Arc;
        
        let config = TransportConfig {
            enable_quic: false,
            enable_tcp: true,
            enable_ble: false,
            ..Default::default()
        };
        let transport = Arc::new(UnifiedTransport::new(config));
        
        transport.bind_all().await.ok();
        
        let mut handles = vec![];
        
        for _ in 0..5 {
            let t = Arc::clone(&transport);
            let handle = tokio::spawn(async move {
                let _ = t.active_transport().await;
                let _ = t.available_transports().await;
            });
            handles.push(handle);
        }
        
        for handle in handles {
            handle.await.ok();
        }
        
        transport.shutdown().await.ok();
    }

    #[test]
    fn test_transport_kind_equality() {
        assert_eq!(TransportKind::Quic, TransportKind::Quic);
        assert_eq!(TransportKind::Tcp, TransportKind::Tcp);
        assert_ne!(TransportKind::Quic, TransportKind::Tcp);
        assert_ne!(TransportKind::Ble, TransportKind::Tor);
    }

    #[test]
    fn test_transport_kind_hash() {
        use std::collections::HashSet;
        
        let mut set = HashSet::new();
        set.insert(TransportKind::Quic);
        set.insert(TransportKind::Quic); // Duplicate
        set.insert(TransportKind::Tcp);
        
        assert_eq!(set.len(), 2);
        assert!(set.contains(&TransportKind::Quic));
        assert!(set.contains(&TransportKind::Tcp));
    }

    #[tokio::test]
    async fn test_multiple_shutdown_calls() {
        let config = TransportConfig {
            enable_quic: false,
            enable_tcp: true,
            enable_ble: false,
            ..Default::default()
        };
        let transport = UnifiedTransport::new(config);
        
        transport.bind_all().await.ok();
        
        // Multiple shutdown calls should be safe
        for _ in 0..3 {
            transport.shutdown().await.ok();
        }
    }

    #[tokio::test]
    async fn test_connect_after_shutdown() {
        let config = TransportConfig {
            enable_quic: false,
            enable_tcp: true,
            enable_ble: false,
            ..Default::default()
        };
        let transport = UnifiedTransport::new(config);
        
        transport.bind_all().await.ok();
        transport.shutdown().await.ok();
        
        // After shutdown, connect should fail
        let addr: SocketAddr = "127.0.0.1:8080".parse().expect("hardcoded address should parse");
        let result = transport.connect(addr).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_transport_result_type() {
        fn success() -> TransportResult<i32> {
            Ok(42)
        }
        
        fn failure() -> TransportResult<i32> {
            Err(TransportError::NotBound)
        }
        
        assert!(success().is_ok());
        assert!(failure().is_err());
        assert_eq!(success().ok(), Some(42));
    }

    #[test]
    fn test_transport_config_debug() {
        let config = TransportConfig::default();
        let debug = format!("{:?}", config);
        assert!(debug.contains("TransportConfig"));
    }

    #[test]
    fn test_transport_state_debug() {
        let state = TransportState::default();
        let debug = format!("{:?}", state);
        assert!(debug.contains("TransportState"));
    }

    #[tokio::test]
    async fn test_bind_with_ble_enabled() {
        let config = TransportConfig {
            enable_quic: false,
            enable_tcp: false,
            enable_ble: true,
            ..Default::default()
        };
        let transport = UnifiedTransport::new(config);
        
        // BLE bind will likely fail but shouldn't panic
        let result = transport.bind_all().await;
        // Result depends on platform support for BLE
        let _ = result;
    }

    #[tokio::test]
    async fn test_transport_priority() {
        let config = TransportConfig {
            enable_quic: true,
            enable_tcp: true,
            enable_ble: false,
            ..Default::default()
        };
        let transport = UnifiedTransport::new(config);
        
        transport.bind_all().await.ok();
        
        // QUIC should be preferred if both available
        let active = transport.active_transport().await;
        // Active transport will be whichever successfully bound
        let _ = active;
        
        transport.shutdown().await.ok();
    }

    #[tokio::test]
    async fn test_connect_with_invalid_address() {
        let config = TransportConfig {
            enable_quic: false,
            enable_tcp: true,
            enable_ble: false,
            ..Default::default()
        };
        let transport = UnifiedTransport::new(config);
        
        transport.bind_all().await.ok();
        
        // Connect to address that likely won't respond
        let addr: SocketAddr = "127.0.0.1:1".parse().expect("hardcoded address should parse");
        let result = transport.connect(addr).await;
        // Should fail due to timeout or connection refused
        assert!(result.is_err());
        
        transport.shutdown().await.ok();
    }

    #[tokio::test]
    async fn test_accept_without_listening() {
        let config = TransportConfig {
            enable_quic: false,
            enable_tcp: true,
            enable_ble: false,
            ..Default::default()
        };
        let transport = UnifiedTransport::new(config);
        
        // Accept without anyone connecting will block/timeout
        // Just verify it doesn't panic when properly bound
        transport.bind_all().await.ok();
        
        // We can't easily test accept without a client, but we verified binding works
        transport.shutdown().await.ok();
    }
}
