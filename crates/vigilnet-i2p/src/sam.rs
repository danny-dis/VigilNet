//! SAM 3.1 Bridge Client
//!
//! Connects to an I2P router's SAM bridge for creating sessions,
//! streams, and datagrams through the I2P network.

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufRead};
use tokio::net::TcpStream;
use tracing::{info, error, warn};

/// SAM session type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    /// Virtual stream (TCP-like)
    Stream,
    /// Datagram (UDP-like, repliable)
    Datagram,
    /// Raw datagram (UDP-like, anonymous)
    Raw,
}

/// SAM bridge client
pub struct SamClient {
    /// SAM bridge address
    bridge_addr: String,
    /// Session ID
    session_id: Option<String>,
    /// I2P destination (our address on the I2P network)
    destination: Option<String>,
    /// Connected state
    connected: bool,
}

impl SamClient {
    /// Create a new SAM client
    pub fn new(bridge_addr: &str) -> Self {
        Self {
            bridge_addr: bridge_addr.to_string(),
            session_id: None,
            destination: None,
            connected: false,
        }
    }

    /// Connect to the SAM bridge with default port
    pub fn default_bridge() -> Self {
        Self::new("127.0.0.1:7656")
    }

    /// Perform SAM handshake (HELLO)
    pub async fn connect(&mut self) -> crate::Result<()> {
        info!("Connecting to SAM bridge at {}", self.bridge_addr);

        let mut stream = TcpStream::connect(&self.bridge_addr).await
            .map_err(|e| crate::I2pError::SamConnectionFailed(e.to_string()))?;

        // Send: HELLO VERSION MIN=3.1 MAX=3.1\n
        stream.write_all(b"HELLO VERSION MIN=3.1 MAX=3.1\n").await?;

        let mut reader = tokio::io::BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response).await?;

        if !response.contains("HELLO REPLY RESULT=OK") {
            return Err(crate::I2pError::SamConnectionFailed(format!("Handshake failed: {}", response)));
        }

        self.connected = true;
        info!("Connected to SAM bridge: {}", response.trim());
        Ok(())
    }

    /// Create a new session
    pub async fn create_session(
        &mut self,
        session_type: SessionType,
        nickname: &str,
    ) -> crate::Result<String> {
        if !self.connected {
            return Err(crate::I2pError::SamConnectionFailed("Not connected".into()));
        }

        let style = match session_type {
            SessionType::Stream => "STREAM",
            SessionType::Datagram => "DATAGRAM",
            SessionType::Raw => "RAW",
        };

        info!("Creating SAM {} session: {}", style, nickname);

        let mut stream = TcpStream::connect(&self.bridge_addr).await?;
        stream.write_all(b"HELLO VERSION MIN=3.1 MAX=3.1\n").await?;
        
        // Skip handshake reply for brevity in this session stream (SAM expects HELLO per connection)
        let mut reader = tokio::io::BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await?;

        // Send: SESSION CREATE STYLE={style} ID={nickname} DESTINATION=TRANSIENT\n
        let cmd = format!("SESSION CREATE STYLE={} ID={} DESTINATION=TRANSIENT\n", style, nickname);
        reader.get_mut().write_all(cmd.as_bytes()).await?;

        let mut response = String::new();
        reader.read_line(&mut response).await?;

        if !response.contains("SESSION STATUS RESULT=OK") {
            return Err(crate::I2pError::SamConnectionFailed(format!("Session creation failed: {}", response)));
        }

        // Extract destination if present
        if let Some(pos) = response.find("DESTINATION=") {
            let dest = response[pos + 12..].trim();
            self.destination = Some(dest.to_string());
        }

        let session_id = nickname.to_string();
        self.session_id = Some(session_id.clone());
        Ok(session_id)
    }

    /// Connect to an I2P destination
    pub async fn stream_connect(&self, destination: &str) -> crate::Result<TcpStream> {
        let session = self.session_id.as_ref()
            .ok_or_else(|| crate::I2pError::SamConnectionFailed("No session".into()))?;

        info!("SAM STREAM CONNECT to {} via session {}", destination, session);
        
        let mut stream = TcpStream::connect(&self.bridge_addr).await?;
        stream.write_all(b"HELLO VERSION MIN=3.1 MAX=3.1\n").await?;
        
        let mut reader = tokio::io::BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await?;

        let cmd = format!("STREAM CONNECT ID={} DESTINATION={}\n", session, destination);
        reader.get_mut().write_all(cmd.as_bytes()).await?;

        let mut response = String::new();
        reader.read_line(&mut response).await?;

        if !response.contains("STREAM STATUS RESULT=OK") {
            return Err(crate::I2pError::SamConnectionFailed(format!("Stream connect failed: {}", response)));
        }

        // Return the stream, positioned at the beginning of the I2P data flow
        Ok(reader.into_inner())
    }

    /// Accept incoming connections
    pub async fn stream_accept(&self) -> crate::Result<()> {
        let session = self.session_id.as_ref()
            .ok_or_else(|| crate::I2pError::SamConnectionFailed("No session".into()))?;

        info!("SAM STREAM ACCEPT on session {}", session);
        // TODO: STREAM ACCEPT ID={session}\n
        Ok(())
    }

    /// Get our I2P destination
    pub fn destination(&self) -> Option<&str> {
        self.destination.as_deref()
    }

    /// Lookup a .i2p hostname via SAM
    pub async fn naming_lookup(&self, hostname: &str) -> crate::Result<String> {
        if !self.connected {
            return Err(crate::I2pError::SamConnectionFailed("Not connected".into()));
        }

        let mut stream = TcpStream::connect(&self.bridge_addr).await?;
        stream.write_all(b"HELLO VERSION MIN=3.1 MAX=3.1\n").await?;
        
        let mut reader = tokio::io::BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await?;

        let cmd = format!("NAMING LOOKUP NAME={}\n", hostname);
        reader.get_mut().write_all(cmd.as_bytes()).await?;

        let mut response = String::new();
        reader.read_line(&mut response).await?;

        if response.contains("NAMING REPLY RESULT=OK") {
            if let Some(pos) = response.find("VALUE=") {
                return Ok(response[pos + 6..].trim().to_string());
            }
        }

        Err(crate::I2pError::NamingError(format!("Lookup failed for {}: {}", hostname, response)))
    }

    /// Close the SAM session
    pub async fn close(&mut self) {
        info!("Closing SAM session");
        self.session_id = None;
        self.destination = None;
        self.connected = false;
    }
}
