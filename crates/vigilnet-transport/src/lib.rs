//! VigilNet Transport
//!
//! Network transport layer supporting multiple protocols:
//! - TCP with Noise encryption
//! - QUIC for NAT traversal
//! - BLE for offline fallback
//! - SecureTransport with Signal Protocol E2EE

pub mod ble;
pub mod quic;
pub mod secure_transport;
pub mod tcp;

pub use ble::BleTransport;
pub use quic::QuicTransport;
pub use secure_transport::{SecureTransport, SessionManager};
pub use tcp::TcpTransport;

use std::io;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Transport not available: {0}")]
    NotAvailable(String),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Session error: {0}")]
    Session(String),

    #[error("Buffer error: {0}")]
    Buffer(String),

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Rate limited: {0}")]
    RateLimited(String),
}

pub type TransportResult<T> = Result<T, TransportError>;

pub trait Transport: Send + Sync {
    fn start(&self) -> TransportResult<()>;
    fn stop(&self) -> TransportResult<()>;
    fn is_running(&self) -> bool;
    fn local_peer_id(&self) -> Option<String>;
}

pub trait Connection: Send + Sync {
    fn peer_id(&self) -> &str;
    fn is_connected(&self) -> bool;
    fn close(&self) -> TransportResult<()>;
}

pub trait MessageSink: Send + Sync {
    fn send(&self, peer_id: &str, data: &[u8]) -> TransportResult<()>;
    fn broadcast(&self, data: &[u8]) -> TransportResult<()>;
}

pub trait MessageSource: Send + Sync {
    fn set_message_handler<F>(&self, handler: F)
    where
        F: Fn(String, Vec<u8>) + Send + Sync + 'static;
}

#[derive(Clone)]
pub struct TransportConfig {
    pub max_connections: usize,
    pub connection_timeout_ms: u64,
    pub read_buffer_size: usize,
    pub write_buffer_size: usize,
    pub keepalive_interval_ms: u64,
    pub max_message_size: usize,
    pub rate_limit_per_sec: u32,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_connections: 256,
            connection_timeout_ms: 30_000,
            read_buffer_size: 64 * 1024,
            write_buffer_size: 64 * 1024,
            keepalive_interval_ms: 30_000,
            max_message_size: 10 * 1024 * 1024,
            rate_limit_per_sec: 1000,
        }
    }
}

#[derive(Clone)]
pub struct ConnectionStats {
    pub bytes_sent: Arc<RwLock<u64>>,
    pub bytes_received: Arc<RwLock<u64>>,
    pub messages_sent: Arc<RwLock<u64>>,
    pub messages_received: Arc<RwLock<u64>>,
    pub connected_at: std::time::Instant,
}

impl ConnectionStats {
    pub fn new() -> Self {
        Self {
            bytes_sent: Arc::new(RwLock::new(0)),
            bytes_received: Arc::new(RwLock::new(0)),
            messages_sent: Arc::new(RwLock::new(0)),
            messages_received: Arc::new(RwLock::new(0)),
            connected_at: std::time::Instant::now(),
        }
    }

    pub async fn record_sent(&self, size: usize) {
        *self.bytes_sent.write().await += size as u64;
        *self.messages_sent.write().await += 1;
    }

    pub async fn record_received(&self, size: usize) {
        *self.bytes_received.write().await += size as u64;
        *self.messages_received.write().await += 1;
    }

    pub async fn stats(&self) -> ConnectionStatsSnapshot {
        ConnectionStatsSnapshot {
            bytes_sent: *self.bytes_sent.read().await,
            bytes_received: *self.bytes_received.read().await,
            messages_sent: *self.messages_sent.read().await,
            messages_received: *self.messages_received.read().await,
            uptime_secs: self.connected_at.elapsed().as_secs(),
        }
    }
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionStatsSnapshot {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub uptime_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_config_defaults() {
        let config = TransportConfig::default();
        assert_eq!(config.max_connections, 256);
        assert_eq!(config.read_buffer_size, 65536);
    }

    #[tokio::test]
    async fn test_connection_stats() {
        let stats = ConnectionStats::new();
        stats.record_sent(100).await;
        stats.record_received(200).await;

        let snapshot = stats.stats().await;
        assert_eq!(snapshot.bytes_sent, 100);
        assert_eq!(snapshot.bytes_received, 200);
        assert_eq!(snapshot.messages_sent, 1);
        assert_eq!(snapshot.messages_received, 1);
    }
}
