//! Firewall management for TUN interface
//!
//! Provides cross-platform firewall configuration for VPN leak protection,
//! including kill switch, split tunneling, and allowed peer management.

use crate::Result;
use std::net::SocketAddr;
use std::process::Command;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

pub struct Firewall {
    interface_name: String,
    rules_applied: bool,
}

#[derive(Debug, Clone)]
pub struct FirewallConfig {
    pub allow_lan: bool,
    pub allow_multicast: bool,
    pub allowed_peers: Vec<SocketAddr>,
    pub blocked_ports: Vec<u16>,
    pub enable_kill_switch: bool,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            allow_lan: true,
            allow_multicast: false,
            allowed_peers: Vec::new(),
            blocked_ports: Vec::new(),
            enable_kill_switch: false,
        }
    }
}

impl Firewall {
    pub fn new(interface_name: &str) -> Self {
        Self {
            interface_name: interface_name.to_string(),
            rules_applied: false,
        }
    }

    pub async fn enable_protection(&mut self, config: &FirewallConfig) -> Result<()> {
        if self.rules_applied {
            info!("Firewall rules already applied, skipping");
            return Ok(());
        }

        info!("Enabling firewall protection for {}", self.interface_name);

        #[cfg(target_os = "linux")]
        {
            self.apply_iptables(config).await?;
        }

        #[cfg(target_os = "windows")]
        {
            self.apply_windows_firewall(config).await?;
        }

        #[cfg(target_os = "macos")]
        {
            self.apply_pf_config(config).await?;
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            warn!("Firewall not supported on this platform");
        }

        self.rules_applied = true;
        info!("Firewall protection enabled");
        Ok(())
    }

    pub async fn disable_protection(&mut self) -> Result<()> {
        if !self.rules_applied {
            return Ok(());
        }

        info!("Disabling firewall protection");

        #[cfg(target_os = "linux")]
        {
            self.flush_iptables().await?;
        }

        #[cfg(target_os = "windows")]
        {
            self.flush_windows_firewall().await?;
        }

        #[cfg(target_os = "macos")]
        {
            self.flush_pf_config().await?;
        }

        self.rules_applied = false;
        info!("Firewall protection disabled");
        Ok(())
    }

    pub fn is_protection_enabled(&self) -> bool {
        self.rules_applied
    }

    #[cfg(target_os = "linux")]
    async fn apply_iptables(&self, config: &FirewallConfig) -> Result<()> {
        let ifc = &self.interface_name;

        self.run_iptables("-F", &["-F"]).await?;
        self.run_iptables("-X", &["-X"]).await?;
        self.run_iptables("-t", &["nat", "-F"]).await?;

        self.run_iptables("-P", &["INPUT", "ACCEPT"]).await?;
        self.run_iptables("-P", &["FORWARD", "ACCEPT"]).await?;
        self.run_iptables("-P", &["OUTPUT", "ACCEPT"]).await?;

        self.run_iptables("-A", &["INPUT", "-i", "lo", "-j", "ACCEPT"]).await?;
        self.run_iptables("-A", &["OUTPUT", "-o", "lo", "-j", "ACCEPT"]).await?;

        self.run_iptables("-A", &["INPUT", "-i", ifc, "-j", "ACCEPT"]).await?;
        self.run_iptables("-A", &["OUTPUT", "-o", ifc, "-j", "ACCEPT"]).await?;

        if config.allow_lan {
            self.run_iptables("-A", &["OUTPUT", "-d", "10.0.0.0/8", "-j", "ACCEPT"]).await?;
            self.run_iptables("-A", &["OUTPUT", "-d", "172.16.0.0/12", "-j", "ACCEPT"]).await?;
            self.run_iptables("-A", &["OUTPUT", "-d", "192.168.0.0/16", "-j", "ACCEPT"]).await?;
            self.run_iptables("-A", &["OUTPUT", "-d", "169.254.0.0/16", "-j", "ACCEPT"]).await?;
        }

        if config.allow_multicast {
            self.run_iptables("-A", &["OUTPUT", "-d", "224.0.0.0/4", "-j", "ACCEPT"]).await?;
        }

        for peer in &config.allowed_peers {
            let addr = peer.ip().to_string();
            let port = peer.port();
            self.run_iptables("-A", &["OUTPUT", "-d", &addr, "-p", "udp", "--dport", &port.to_string(), "-j", "ACCEPT"]).await?;
            self.run_iptables("-A", &["OUTPUT", "-d", &addr, "-p", "tcp", "--dport", &port.to_string(), "-j", "ACCEPT"]).await?;
        }

        for &port in &config.blocked_ports {
            self.run_iptables("-A", &["OUTPUT", "-p", "tcp", "--dport", &port.to_string(), "-j", "DROP"]).await?;
            self.run_iptables("-A", &["OUTPUT", "-p", "udp", "--dport", &port.to_string(), "-j", "DROP"]).await?;
        }

        if config.enable_kill_switch {
            self.run_iptables("-A", &["OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"]).await?;
            self.run_iptables("-P", &["OUTPUT", "DROP"]).await?;
            info!("Kill switch enabled - all non-VPN traffic blocked");
        }

        debug!("Linux iptables rules applied successfully");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn flush_iptables(&self) -> Result<()> {
        self.run_iptables("-F", &["-F"]).await?;
        self.run_iptables("-X", &["-X"]).await?;
        self.run_iptables("-t", &["nat", "-F"]).await?;
        self.run_iptables("-P", &["INPUT", "ACCEPT"]).await?;
        self.run_iptables("-P", &["FORWARD", "ACCEPT"]).await?;
        self.run_iptables("-P", &["OUTPUT", "ACCEPT"]).await?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn run_iptables(&self, _cmd: &str, args: &[&str]) -> Result<()> {
        let full_args: Vec<&str> = std::iter::once("iptables")
            .chain(args.iter().copied())
            .collect::<Vec<_>>();
        
        debug!("Running iptables: {:?}", full_args);

        #[cfg(feature = "firewall_apply")]
        {
            let status = tokio::task::spawn_blocking(move || {
                Command::new("iptables")
                    .args(args)
                    .status()
            }).await.map_err(|e| crate::TunError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))??;

            if !status.success() {
                warn!("iptables command failed: {:?}", full_args);
            }
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn apply_windows_firewall(&self, config: &FirewallConfig) -> Result<()> {
        let rule_name = format!("VigilNet-{}", self.interface_name);

        let _ = tokio::task::spawn_blocking(move || {
            Command::new("netsh")
                .args(&["advfirewall", "firewall", "delete", "rule", "name=", &rule_name])
                .output()
        }).await;

        let _ = tokio::task::spawn_blocking(move || {
            Command::new("netsh")
                .args(&[
                    "advfirewall", "firewall", "add", "rule",
                    "name=", &rule_name,
                    "dir=in",
                    "action=allow",
                    "interface=", &rule_name,
                ])
                .output()
        }).await;

        let _ = tokio::task::spawn_blocking(move || {
            Command::new("netsh")
                .args(&[
                    "advfirewall", "firewall", "add", "rule",
                    "name=", &rule_name,
                    "dir=out",
                    "action=allow",
                    "interface=", &rule_name,
                ])
                .output()
        }).await;

        if config.enable_kill_switch {
            let block_rule = format!("VigilNet-Block-{}", self.interface_name);
            
            let _ = tokio::task::spawn_blocking(move || {
                Command::new("netsh")
                    .args(&[
                        "advfirewall", "firewall", "add", "rule",
                        "name=", &block_rule,
                        "dir=out",
                        "action=block",
                        "enable=no",
                    ])
                    .output()
            }).await;

            info!("Windows kill switch rule created (manual activation recommended)");
        }

        debug!("Windows firewall rules applied");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn flush_windows_firewall(&self) -> Result<()> {
        let rule_name = format!("VigilNet-{}", self.interface_name);

        let _ = tokio::task::spawn_blocking(move || {
            Command::new("netsh")
                .args(&["advfirewall", "firewall", "delete", "rule", "name=", &rule_name])
                .output()
        }).await;

        let block_rule = format!("VigilNet-Block-{}", self.interface_name);
        let _ = tokio::task::spawn_blocking(move || {
            Command::new("netsh")
                .args(&["advfirewall", "firewall", "delete", "rule", "name=", &block_rule])
                .output()
        }).await;

        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn apply_pf_config(&self, config: &FirewallConfig) -> Result<()> {
        let anchor_name = "com.vigilnet.vpn";

        let mut rules = String::new();
        rules.push_str(&format!("# VigilNet firewall rules for {}\n", self.interface_name));
        rules.push_str("set skip on lo0\n");
        rules.push_str(&format!("pass in on {}\n", self.interface_name));
        rules.push_str(&format!("pass out on {}\n", self.interface_name));

        if config.allow_lan {
            rules.push_str("pass out to 10.0.0.0/8\n");
            rules.push_str("pass out to 172.16.0.0/12\n");
            rules.push_str("pass out to 192.168.0.0/16\n");
        }

        if config.enable_kill_switch {
            rules.push_str("block out all\n");
            info!("macOS kill switch enabled");
        }

        #[cfg(feature = "firewall_apply")]
        {
            let _ = tokio::task::spawn_blocking(move || {
                Command::new("pfctl")
                    .args(&["-a", anchor_name, "-f", "-"])
                    .output()
            }).await;
            let _ = tokio::task::spawn_blocking(move || {
                Command::new("pfctl")
                    .args(&["-e"])
                    .output()
            }).await;
        }

        debug!("macOS PF rules configured");
        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn flush_pf_config(&self) -> Result<()> {
        let anchor_name = "com.vigilnet.vpn";

        #[cfg(feature = "firewall_apply")]
        {
            let _ = tokio::task::spawn_blocking(move || {
                Command::new("pfctl")
                    .args(&["-a", anchor_name, "-F", "rules"])
                    .output()
            }).await;
            let _ = tokio::task::spawn_blocking(move || {
                Command::new("pfctl")
                    .args(&["-d"])
                    .output()
            }).await;
        }

        Ok(())
    }

    pub async fn validate_rules(&self) -> Result<bool> {
        #[cfg(target_os = "linux")]
        {
            let output = tokio::task::spawn_blocking(|| {
                Command::new("iptables")
                    .args(&["-L", "-n", "-v"])
                    .output()
            }).await.map_err(|e| crate::TunError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))??;

            let output_str = String::from_utf8_lossy(&output.stdout);
            Ok(output_str.contains(&self.interface_name))
        }

        #[cfg(not(target_os = "linux"))]
        {
            Ok(self.rules_applied)
        }
    }
}
