//! VPN Service Integration
//!
//! Handles Android VpnService TUN file descriptor passthrough
//! and packet processing via the Rust networking stack.

#[cfg(unix)]
use std::os::fd::RawFd;

#[cfg(not(unix))]
type RawFd = i32;

use tokio::sync::mpsc;
use tracing::{info, warn, error, debug};

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
    pub data: Vec<u8>,
}

/// VPN Tunnel manager
///
/// Wraps the TUN file descriptor received from Android's VpnService
/// and processes packets through the VigilNet routing stack.
pub struct VpnTunnel {
    /// Current state
    state: TunnelState,
    /// Statistics
    stats: TunnelStats,
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
}

impl VpnTunnel {
    /// Create a new VPN tunnel
    pub fn new() -> Self {
        Self {
            state: TunnelState::Disconnected,
            stats: TunnelStats::default(),
            tun_fd: None,
            mtu: 1500,
            dns_servers: vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()],
            excluded_apps: Vec::new(),
            shutdown_tx: None,
            packet_tx: None,
            packet_rx: None,
        }
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
        info!("VPN tunnel connected");

        let mtu = self.mtu as usize;

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
                                let data = buf[..n].to_vec();
                                // Parse check (optional logging)
                                if let Ok((header, _)) = etherparse::Ipv4Header::from_slice(&data) {
                                    debug!("TUN read: {} -> {} ({} bytes)", 
                                        std::net::Ipv4Addr::from(header.source), 
                                        std::net::Ipv4Addr::from(header.destination),
                                        n
                                    );
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
        tokio::spawn(async move {
            loop {
                // We can't easily select on packet_rx and a shutdown signal if packet_rx is the only source
                // But if the read loop shuts down, it triggered the shutdown signal.
                // For simplicity, we just listen on packet_rx. If packet_tx is dropped by NM, this returns None.
                match packet_rx.recv().await {
                    Some(packet) => {
                        #[cfg(unix)]
                        {
                            if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut writer, &packet.data).await {
                                error!("Failed to write to TUN: {}", e);
                                break;
                            }
                            debug!("TUN write: {} bytes", packet.data.len());
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
        info!("VPN tunnel stopped");
        Ok(())
    }

    /// Get current tunnel state
    pub fn state(&self) -> TunnelState {
        self.state
    }

    /// Get tunnel statistics
    pub fn stats(&self) -> &TunnelStats {
        &self.stats
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
