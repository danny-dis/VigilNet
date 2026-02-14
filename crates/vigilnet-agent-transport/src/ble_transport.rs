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

    async fn connect(&self, addr: SocketAddr) -> TransportResult<Box<dyn AgentConnection>> {
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
