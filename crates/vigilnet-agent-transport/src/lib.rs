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
