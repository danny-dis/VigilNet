//! TUN device management
//!
//! Provides cross-platform TUN device creation and management for VPN functionality.

use crate::dhcp_guard::DhcpGuard;
use crate::firewall::Firewall;
use crate::packet::IpPacket;
use crate::{Result, TunError};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone)]
pub struct TunConfig {
    pub name: String,
    pub mtu: u16,
    pub address: IpAddr,
    pub netmask: IpAddr,
    pub set_default_route: bool,
    pub enable_firewall: bool,
    pub enable_dhcp_guard: bool,
    pub firewall_config: crate::firewall::FirewallConfig,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "vigilnet0".to_string(),
            mtu: 1500,
            address: IpAddr::V4("10.0.0.1".parse().unwrap()),
            netmask: IpAddr::V4("255.255.255.0".parse().unwrap()),
            set_default_route: false,
            enable_firewall: false,
            enable_dhcp_guard: false,
            firewall_config: crate::firewall::FirewallConfig::default(),
        }
    }
}

impl TunConfig {
    pub fn new(name: &str, address: IpAddr, netmask: IpAddr) -> Self {
        Self {
            name: name.to_string(),
            mtu: 1500,
            address,
            netmask,
            set_default_route: false,
            enable_firewall: false,
            enable_dhcp_guard: false,
            firewall_config: crate::firewall::FirewallConfig::default(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::default()
    }

    pub fn with_firewall(mut self, enable: bool) -> Self {
        self.enable_firewall = enable;
        self
    }

    pub fn with_dhcp_guard(mut self, enable: bool) -> Self {
        self.enable_dhcp_guard = enable;
        self
    }

    pub fn with_default_route(mut self, enable: bool) -> Self {
        self.set_default_route = enable;
        self
    }
}

pub struct TunDevice {
    config: TunConfig,
    active: bool,
    firewall: Option<Arc<RwLock<Firewall>>>,
    dhcp_guard: DhcpGuard,
    packet_sender: Option<mpsc::Sender<Vec<u8>>>,
    packet_receiver: Arc<RwLock<Option<mpsc::Receiver<Vec<u8>>>>>,
}

impl TunDevice {
    pub fn new(config: TunConfig) -> Self {
        let firewall = if config.enable_firewall {
            Some(Arc::new(RwLock::new(Firewall::new(&config.name))))
        } else {
            None
        };

        Self {
            config,
            active: false,
            firewall,
            dhcp_guard: DhcpGuard::new(),
            packet_sender: None,
            packet_receiver: Arc::new(RwLock::new(None)),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(TunConfig::default())
    }

    pub fn name(&self) -> &str {
        &self.config.name
    }

    pub fn config(&self) -> &TunConfig {
        &self.config
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub async fn up(&mut self) -> Result<()> {
        if self.active {
            return Ok(());
        }

        info!("Creating TUN device: {}", self.config.name);

        #[cfg(target_os = "linux")]
        {
            self.setup_linux_device().await?;
        }

        #[cfg(target_os = "windows")]
        {
            self.setup_windows_device().await?;
        }

        #[cfg(target_os = "macos")]
        {
            self.setup_macos_device().await?;
        }

        if let Some(firewall) = &self.firewall {
            let mut config = self.config.firewall_config.clone();
            config.enable_kill_switch = self.config.set_default_route;
            firewall.write().await.enable_protection(&config).await?;
        }

        self.active = true;
        info!("TUN device {} is up", self.config.name);
        Ok(())
    }

    pub async fn down(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }

        warn!("Bringing down TUN device: {}", self.config.name);

        if let Some(firewall) = &self.firewall {
            firewall.write().await.disable_protection().await?;
        }

        #[cfg(target_os = "linux")]
        {
            self.cleanup_linux_device().await?;
        }

        self.active = false;
        info!("TUN device {} is down", self.config.name);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn setup_linux_device(&self) -> Result<()> {
        use std::process::Command;

        let name = &self.config.name;

        let result = Command::new("ip")
            .args(&["tuntap", "add", "mode", "tun", "user", "root"])
            .args(&["name", name])
            .output();

        if let Ok(output) = result {
            if !output.status.success() {
                debug!("TUN device may already exist or needs manual creation");
            }
        }

        let addr = match self.config.address {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => ip.to_string(),
        };

        let _ = Command::new("ip")
            .args(&["link", "set", name, "up"])
            .output();

        let _ = Command::new("ip")
            .args(&["addr", "add", &format!("{}/24", addr), "dev", name])
            .output();

        if self.config.set_default_route {
            let _ = Command::new("ip")
                .args(&["route", "add", "default", "dev", name])
                .output();
            info!("Default route added via {}", name);
        }

        let _ = Command::new("ip")
            .args(&["link", "set", "mtu", &self.config.mtu.to_string(), "dev", name])
            .output();

        info!("Linux TUN device {} configured", name);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn cleanup_linux_device(&self) -> Result<()> {
        use std::process::Command;

        let name = &self.config.name;

        if self.config.set_default_route {
            let _ = Command::new("ip")
                .args(&["route", "del", "default", "dev", name])
                .output();
        }

        let _ = Command::new("ip")
            .args(&["link", "set", name, "down"])
            .output();

        let _ = Command::new("ip")
            .args(&["tuntap", "del", "mode", "tun"])
            .output();

        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn setup_windows_device(&self) -> Result<()> {
        use std::process::Command;

        info!("Windows TUN device setup - requires Wintun driver");
        
        let _ = Command::new("netsh")
            .args(&[
                "interface", "ipv4", "add", "address",
                &self.config.name,
                "10.0.0.1",
                "255.255.255.0",
            ])
            .output();

        info!("Windows TUN interface configured");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn cleanup_windows_device(&self) -> Result<()> {
        use std::process::Command;

        let _ = Command::new("netsh")
            .args(&["interface", "set", "interface", &self.config.name, "disable"])
            .output();

        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn setup_macos_device(&self) -> Result<()> {
        use std::process::Command;

        let name = &self.config.name;

        let result = Command::new("ipconfig")
            .args(&["utun", "enable", name])
            .output();

        if let Ok(output) = result {
            if !output.status.success() {
                debug!("UTUN device may need manual creation");
            }
        }

        let addr = match self.config.address {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => ip.to_string(),
        };

        let _ = Command::new("ifconfig")
            .args(&[name, "inet", &addr, "netmask", "255.255.255.0", "up"])
            .output();

        if self.config.set_default_route {
            let _ = Command::new("route")
                .args(&["add", "-net", "0.0.0.0", "-interface", name])
                .output();
        }

        info!("macOS UTUN device configured");
        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn cleanup_macos_device(&self) -> Result<()> {
        use std::process::Command;

        if self.config.set_default_route {
            let _ = Command::new("route")
                .args(&["delete", "-net", "0.0.0.0", "-interface", &self.config.name])
                .output();
        }

        Ok(())
    }

    pub async fn read_packet(&self) -> Result<Vec<u8>> {
        if !self.active {
            return Err(TunError::NotReady);
        }

        if let Some(receiver) = self.packet_receiver.read().await.as_ref() {
            match receiver.recv().await {
                Some(packet) => Ok(packet),
                None => Err(TunError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Packet channel closed"
                ))),
            }
        } else {
            Err(TunError::NotReady)
        }
    }

    pub async fn write_packet(&self, data: &[u8]) -> Result<()> {
        if !self.active {
            return Err(TunError::NotReady);
        }

        if let Some(packet) = IpPacket::parse(data) {
            if self.config.enable_dhcp_guard {
                if !self.dhcp_guard.validate_outbound(data) {
                    warn!("DHCP guard blocked outbound packet");
                    return Ok(());
                }
            }

            debug!(
                "Outbound: {} {} -> {} ({} bytes)",
                packet.protocol_name(),
                packet.src_addr_str(),
                packet.dst_addr_str(),
                data.len()
            );
        }

        if let Some(sender) = &self.packet_sender {
            sender.send(data.to_vec()).await.ok();
        }

        Ok(())
    }

    pub async fn process_inbound(&self, data: &[u8]) -> Result<Option<Vec<u8>>> {
        if !self.active {
            return Err(TunError::NotReady);
        }

        if let Some(packet) = IpPacket::parse(data) {
            if self.config.enable_dhcp_guard {
                if !self.dhcp_guard.validate_inbound(data) {
                    debug!("DHCP guard blocked inbound packet");
                    return Ok(None);
                }
            }

            debug!(
                "Inbound: {} {} -> {} ({} bytes)",
                packet.protocol_name(),
                packet.src_addr_str(),
                packet.dst_addr_str(),
                data.len()
            );

            if packet.dst_addr.is_multicast() && !self.config.firewall_config.allow_multicast {
                debug!("Multicast packet blocked");
                return Ok(None);
            }

            return Ok(Some(data.to_vec()));
        }

        Ok(None)
    }

    pub fn get_stats(&self) -> TunStats {
        TunStats {
            active: self.active,
            mtu: self.config.mtu,
            name: self.config.name.clone(),
            address: self.config.address.to_string(),
        }
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        if self.active {
            let name = self.config.name.clone();
            error!("TUN device {} dropped while still active!", name);
        }
    }
}

#[derive(Debug, Clone)]
pub struct TunStats {
    pub active: bool,
    pub mtu: u16,
    pub name: String,
    pub address: String,
}

pub struct TunBuilder {
    config: TunConfig,
}

impl TunBuilder {
    pub fn new() -> Self {
        Self {
            config: TunConfig::default(),
        }
    }

    pub fn name(mut self, name: &str) -> Self {
        self.config.name = name.to_string();
        self
    }

    pub fn address(mut self, addr: IpAddr) -> Self {
        self.config.address = addr;
        self
    }

    pub fn mtu(mut self, mtu: u16) -> Self {
        self.config.mtu = mtu;
        self
    }

    pub fn enable_firewall(mut self) -> Self {
        self.config.enable_firewall = true;
        self
    }

    pub fn enable_dhcp_guard(mut self) -> Self {
        self.config.enable_dhcp_guard = true;
        self
    }

    pub fn default_route(mut self) -> Self {
        self.config.set_default_route = true;
        self
    }

    pub fn build(self) -> TunDevice {
        TunDevice::new(self.config)
    }
}

impl Default for TunBuilder {
    fn default() -> Self {
        Self::new()
    }
}
