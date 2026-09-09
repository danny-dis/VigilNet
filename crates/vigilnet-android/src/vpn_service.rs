//! VPN Service Integration
//!
//! Handles Android VpnService TUN file descriptor passthrough
//! and packet processing via the Rust networking stack.
//! Includes improved reconnection logic and state management.

#[cfg(unix)]
use std::os::fd::RawFd;

#[cfg(not(unix))]
type RawFd = i32;

use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn, error, debug};
use async_trait::async_trait;

/// VPN tunnel state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    /// Not connected
    Disconnected,
    /// Establishing connection
    Connecting,
    /// VPN active and routing traffic
    Connected,
    /// Disconnecting
    Disconnecting,
}

/// Statistics for the VPN tunnel
#[derive(Debug, Clone, Default)]
pub struct TunnelStats {
    /// Total bytes sent through tunnel
    pub bytes_sent: u64,
    /// Total bytes received through tunnel
    pub bytes_received: u64,
    /// Packets sent
    pub packets_sent: u64,
    /// Packets received
    pub packets_received: u64,
    /// Active connections
    pub active_connections: u32,
}

/// IP packet captured from TUN interface
#[derive(Debug, Clone)]
pub struct TunPacket {
    pub data: bytes::Bytes,
}

impl TunPacket {
    pub fn new(data: bytes::Bytes) -> Self {
        Self { data }
    }

    pub fn from_vec(data: Vec<u8>) -> Self {
        Self { data: bytes::Bytes::from(data) }
    }
}

/// Trait for VPN tunnel event listeners
#[async_trait]
pub trait VpnEventListener: Send + Sync {
    async fn on_connect(&self);
    async fn on_disconnect(&self);
    async fn on_error(&self, error: &str);
    async fn on_stats_update(&self, stats: &TunnelStats);
}

/// VPN Tunnel manager
///
/// Wraps the TUN file descriptor received from Android's VpnService
/// and processes packets through the VigilNet routing stack.
pub struct VpnTunnel {
    /// Current state
    state: TunnelState,
    /// Statistics
    stats: Arc<RwLock<TunnelStats>>,
    /// TUN file descriptor (from Android VpnService)
    tun_fd: Option<RawFd>,
    /// MTU size
    mtu: u16,
    /// DNS servers
    dns_servers: Vec<String>,
    /// Excluded apps (package names)
    excluded_apps: Vec<String>,
    /// Shutdown signal
    shutdown_tx: Option<mpsc::Sender<()>>,
    /// Channel to send captured packets to NetworkManager
    packet_tx: Option<mpsc::Sender<TunPacket>>,
    /// Channel to receive packets to write to TUN (from NetworkManager)
    packet_rx: Option<mpsc::Receiver<TunPacket>>,
    /// Event listeners
    listeners: Vec<Arc<dyn VpnEventListener>>,
    /// Whether reconnection is enabled
    auto_reconnect: bool,
    /// Reconnection delay in seconds
    reconnect_delay_secs: u64,
}

impl VpnTunnel {
    /// Create a new VPN tunnel
    pub fn new() -> Self {
        Self {
            state: TunnelState::Disconnected,
            stats: Arc::new(RwLock::new(TunnelStats::default())),
            tun_fd: None,
            mtu: 1500,
            dns_servers: vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()],
            excluded_apps: Vec::new(),
            shutdown_tx: None,
            packet_tx: None,
            packet_rx: None,
            listeners: Vec::new(),
            auto_reconnect: true,
            reconnect_delay_secs: 5,
        }
    }

    /// Add an event listener
    pub fn add_listener(&mut self, listener: Arc<dyn VpnEventListener>) {
        self.listeners.push(listener);
    }

    /// Set auto-reconnect
    pub fn set_auto_reconnect(&mut self, enabled: bool, delay_secs: u64) {
        self.auto_reconnect = enabled;
        self.reconnect_delay_secs = delay_secs;
    }

    /// Set the packet channels
    pub fn set_channels(
        &mut self,
        tx: mpsc::Sender<TunPacket>,
        rx: mpsc::Receiver<TunPacket>,
    ) {
        self.packet_tx = Some(tx);
        self.packet_rx = Some(rx);
    }

    /// Set the TUN file descriptor from Android VpnService
    ///
    /// On Android, the VpnService.Builder creates a TUN device and
    /// returns a ParcelFileDescriptor. The fd is extracted and passed
    /// to this method via JNI.
    pub fn set_tun_fd(&mut self, fd: RawFd) {
        info!("Setting TUN file descriptor: {}", fd);
        self.tun_fd = Some(fd);
    }

    /// Set MTU
    pub fn set_mtu(&mut self, mtu: u16) {
        self.mtu = mtu;
    }

    /// Set DNS servers
    pub fn set_dns_servers(&mut self, servers: Vec<String>) {
        self.dns_servers = servers;
    }

    /// Add an excluded app
    pub fn exclude_app(&mut self, package_name: String) {
        self.excluded_apps.push(package_name);
    }

    /// Start the VPN tunnel
    ///
    /// Begins reading IP packets from the TUN fd and routing them
    /// through the appropriate network backend.
    pub async fn start(&mut self) -> crate::Result<()> {
        let fd = self.tun_fd.ok_or_else(|| {
            crate::AndroidError::VpnError("TUN fd not set. Call set_tun_fd first.".into())
        })?;

        let packet_tx = self.packet_tx.clone().ok_or_else(|| {
            crate::AndroidError::VpnError("Packet TX channel not set".into())
        })?;
        
        let mut packet_rx = self.packet_rx.take().ok_or_else(|| {
            crate::AndroidError::VpnError("Packet RX channel not set".into())
        })?;

        self.state = TunnelState::Connecting;
        info!("Starting VPN tunnel with fd={}, mtu={}", fd, self.mtu);

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        // Create TUN device
        #[cfg(unix)]
        let (mut reader, mut writer) = {
            let mut config = tun_rs::Configuration::default();
            config.raw_fd(fd);
            let device = tun_rs::create_as_async(&config).map_err(|e| crate::AndroidError::VpnError(e.to_string()))?;
            tokio::io::split(device)
        };

        self.state = TunnelState::Connected;
        
        // Notify listeners
        self.notify_connect().await;
        
        info!("VPN tunnel connected");

        let mtu = self.mtu as usize;
        let stats = self.stats.clone();

        // READ LOOP: TUN -> NetworkManager
        tokio::spawn(async move {
            let mut buf = vec![0u8; mtu];
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        info!("VPN read loop shutting down");
                        break;
                    }
                    #[cfg(unix)]
                    res = tokio::io::AsyncReadExt::read(&mut reader, &mut buf) => {
                        match res {
                            Ok(n) => {
                                if n == 0 { break; } // EOF
                                let data = bytes::Bytes::copy_from_slice(&buf[..n]);
                                // Parse check (optional logging)
                                if let Ok((header, _)) = etherparse::Ipv4Header::from_slice(&data) {
                                    trace!("TUN read: {} -> {} ({} bytes)", 
                                        std::net::Ipv4Addr::from(header.source), 
                                        std::net::Ipv4Addr::from(header.destination),
                                        n
                                    );
                                }
                                
                                // Update stats
                                {
                                    let mut s = stats.write().await;
                                    s.bytes_received += n as u64;
                                    s.packets_received += 1;
                                }
                                
                                // Send to NetworkManager
                                if let Err(e) = packet_tx.send(TunPacket { data }).await {
                                    error!("Failed to send packet to NM: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                error!("Failed to read from TUN: {}", e);
                                break;
                            }
                        }
                    }
                    #[cfg(not(unix))]
                    _ = tokio::time::sleep(std::time::Duration::from_secs(3600)) => {}
                }
            }
        });

        // WRITE LOOP: NetworkManager -> TUN
        let stats_write = self.stats.clone();
        tokio::spawn(async move {
            loop {
                match packet_rx.recv().await {
                    Some(packet) => {
                        #[cfg(unix)]
                        {
                            if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut writer, &packet.data).await {
                                error!("Failed to write to TUN: {}", e);
                                break;
                            }
                            trace!("TUN write: {} bytes", packet.data.len());
                        }
                        
                        // Update stats
                        {
                            let mut s = stats_write.write().await;
                            s.bytes_sent += packet.data.len() as u64;
                            s.packets_sent += 1;
                        }
                        
                        #[cfg(not(unix))]
                        {
                            debug!("VPN write stub: {} bytes", packet.data.len());
                        }
                    }
                    None => {
                        info!("Packet RX channel closed, stopping write loop");
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop the VPN tunnel
    pub async fn stop(&mut self) -> crate::Result<()> {
        self.state = TunnelState::Disconnecting;
        info!("Stopping VPN tunnel");

        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }

        self.state = TunnelState::Disconnected;
        self.tun_fd = None;
        
        // Notify listeners
        self.notify_disconnect().await;
        
        info!("VPN tunnel stopped");
        Ok(())
    }

    async fn notify_connect(&self) {
        for listener in &self.listeners {
            listener.on_connect().await;
        }
    }

    async fn notify_disconnect(&self) {
        for listener in &self.listeners {
            listener.on_disconnect().await;
        }
    }

    async fn notify_error(&self, error: &str) {
        for listener in &self.listeners {
            listener.on_error(error).await;
        }
    }

    /// Get current tunnel state
    pub fn state(&self) -> TunnelState {
        self.state
    }

    /// Get tunnel statistics (cloned)
    pub async fn stats(&self) -> TunnelStats {
        self.stats.read().await.clone()
    }

    /// Get stats as a reference for real-time updates
    pub fn stats_ref(&self) -> Arc<RwLock<TunnelStats>> {
        self.stats.clone()
    }

    /// Check if tunnel is active
    pub fn is_active(&self) -> bool {
        self.state == TunnelState::Connected
    }
}

impl Default for VpnTunnel {
    fn default() -> Self {
        Self::new()
    }
}
