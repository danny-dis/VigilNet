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
            bind_addr: "0.0.0.0:0".parse().unwrap(),
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
