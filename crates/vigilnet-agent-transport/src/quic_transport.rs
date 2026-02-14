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
            bind_addr: "0.0.0.0:0".parse().unwrap(),
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
            .ok_or(TransportError::ConnectionFailed("Endpoint closed".into()))?;

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
