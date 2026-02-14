//! I2P Naming / Address Book
//!
//! Resolves .i2p hostnames to I2P destinations.

use std::collections::HashMap;
use tracing::{info, debug};

/// I2P naming service
pub struct NamingService {
    /// Local address book (hostname -> base64 destination)
    address_book: HashMap<String, String>,
}

impl NamingService {
    /// Create with empty address book
    pub fn new() -> Self {
        Self {
            address_book: HashMap::new(),
        }
    }

    /// Add an entry
    pub fn add(&mut self, hostname: &str, destination: &str) {
        debug!("Adding naming entry: {} -> {}...", hostname, &destination[..20.min(destination.len())]);
        self.address_book.insert(hostname.to_string(), destination.to_string());
    }

    /// Lookup a .i2p hostname
    pub fn lookup(&self, hostname: &str) -> Option<&str> {
        self.address_book.get(hostname).map(|s| s.as_str())
    }

    /// Load address book from file (hosts.txt format)
    pub fn load_hosts_txt(&mut self, content: &str) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((host, dest)) = line.split_once('=') {
                self.add(host.trim(), dest.trim());
            }
        }
        info!("Loaded {} naming entries", self.address_book.len());
    }
}

impl Default for NamingService {
    fn default() -> Self {
        Self::new()
    }
}
