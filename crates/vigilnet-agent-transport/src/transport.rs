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
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Quic => write!(f, "QUIC"),
            Self::Tcp => write!(f, "TCP"),
            Self::Ble => write!(f, "BLE"),
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

        if state.active_transport.is_none() {
            return Err(TransportError::AllTransportsFailed);
        }

        info!(
            active = %state.active_transport.unwrap(),
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
                    .ok_or(TransportError::NotAvailable("QUIC not enabled".into()))?;
                quic.read().await.connect(addr).await
            }
            TransportKind::Tcp => {
                let tcp = self
                    .tcp
                    .as_ref()
                    .ok_or(TransportError::NotAvailable("TCP not enabled".into()))?;
                tcp.read().await.connect(addr).await
            }
            TransportKind::Ble => {
                let ble = self
                    .ble
                    .as_ref()
                    .ok_or(TransportError::NotAvailable("BLE not enabled".into()))?;
                ble.read().await.connect(addr).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_kind_display() {
        assert_eq!(TransportKind::Quic.to_string(), "QUIC");
        assert_eq!(TransportKind::Tcp.to_string(), "TCP");
        assert_eq!(TransportKind::Ble.to_string(), "BLE");
    }

    #[test]
    fn test_default_config() {
        let config = TransportConfig::default();
        assert!(config.enable_quic);
        assert!(config.enable_tcp);
        assert!(!config.enable_ble);
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

        transport.shutdown().await.unwrap();
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
        transport.bind_all().await.unwrap();

        let available = transport.available_transports().await;
        assert!(available.contains(&TransportKind::Tcp));
        assert!(!available.contains(&TransportKind::Ble));

        transport.shutdown().await.unwrap();
    }
}
