//! Network namespace isolation for Linux
//!
//! Provides namespace-based network isolation to prevent VPN leaks.

use crate::{Result, TunError};
use std::process::Command;
use tracing::{debug, info, warn};

pub struct NamespaceIsolation;

impl NamespaceIsolation {
    #[cfg(target_os = "linux")]
    pub fn create_vpn_namespace(tun_name: &str) -> Result<()> {
        info!("Creating VPN namespace 'vigilnet_vpn'...");

        let ns_name = "vigilnet_vpn";

        let check = Command::new("ip")
            .args(&["netns", "list"])
            .output()
            .map_err(|e| TunError::Io(e))?;

        let output_str = String::from_utf8_lossy(&check.stdout);
        if output_str.contains(ns_name) {
            info!("Namespace {} already exists, removing first", ns_name);
            Self::delete_namespace(ns_name)?;
        }

        Self::run_cmd("ip", &["netns", "add", ns_name])?;

        Self::run_cmd("ip", &["link", "set", tun_name, "netns", ns_name])?;

        Self::run_cmd("ip", &["netns", "exec", ns_name, "ip", "link", "set", "lo", "up"])?;
        Self::run_cmd("ip", &["netns", "exec", ns_name, "ip", "link", "set", tun_name, "up"])?;

        info!(
            "Namespace '{}' created successfully. Run apps with: ip netns exec {} <command>",
            ns_name, ns_name
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn delete_namespace(name: &str) -> Result<()> {
        debug!("Deleting namespace '{}'...", name);
        let _ = Self::run_cmd("ip", &["netns", "del", name]);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn list_namespaces() -> Result<Vec<String>> {
        let output = Command::new("ip")
            .args(&["netns", "list"])
            .output()
            .map_err(|e| TunError::Io(e))?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let namespaces: Vec<String> = output_str
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| line.split_whitespace().next().unwrap_or("").to_string())
            .filter(|name| !name.is_empty())
            .collect();

        Ok(namespaces)
    }

    #[cfg(target_os = "linux")]
    pub fn execute_in_namespace<T>(name: &str, command: &[&str]) -> Result<T>
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Debug,
    {
        let mut args = vec!["netns", "exec", name];
        args.extend(command);

        let output = Command::new("ip")
            .args(&args)
            .output()
            .map_err(|e| TunError::Io(e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(TunError::CreationFailed(format!(
                "Command in namespace failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .trim()
            .parse()
            .map_err(|_| TunError::CreationFailed("Parse error".to_string()))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn create_vpn_namespace(_tun_name: &str) -> Result<()> {
        warn!("Namespace isolation is only supported on Linux.");
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn delete_namespace(_name: &str) -> Result<()> {
        warn!("Namespace isolation is only supported on Linux.");
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn list_namespaces() -> Result<Vec<String>> {
        warn!("Namespace isolation is only supported on Linux.");
        Ok(Vec::new())
    }

    fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
        let output = Command::new(cmd)
            .args(args)
            .output()
            .map_err(|e| TunError::Io(e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(TunError::CreationFailed(format!(
                "Command '{} {:?}' failed: {}",
                cmd, args, stderr
            )));
        }

        debug!("Command '{} {:?}' succeeded", cmd, args);
        Ok(())
    }
}
