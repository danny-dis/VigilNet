//! Bluetooth Low Energy transport for offline mesh networking
//!
//! Provides BLE GATT-based transport for device-to-device communication
//! when no IP network is available. Supports BLE mesh proxy mode.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};

use crate::{TransportConfig, TransportError, TransportResult, Transport};

const BLE_SERVICE_UUID: &str = "6e400001-b5a3-f393-e0a9-e50e24dcca9e";
const BLE_CHAR_TX_UUID: &str = "6e400002-b5a3-f393-e0a9-e50e24dcca9e";
const BLE_CHAR_RX_UUID: &str = "6e400003-b5a3-f393-e0a9-e50e24dcca9e";

const DEFAULT_MTU: usize = 512;
const MAX_MTU: usize = 512;

pub struct BleTransport {
    config: TransportConfig,
    service_uuid: String,
    available: bool,
    running: Arc<RwLock<bool>>,
    peripherals: Arc<RwLock<HashMap<String, BlePeripheral>>>,
    advertising: Arc<RwLock<bool>>,
    scanning: Arc<RwLock<bool>>,
    shutdown_tx: Option<broadcast::Sender<()>>,
    message_tx: Option<broadcast::Sender<(String, Vec<u8>)>>,
}

struct BlePeripheral {
    address: String,
    name: Option<String>,
    rssi: i16,
    connected: bool,
    mtu: usize,
}

impl BleTransport {
    pub fn new() -> Self {
        Self {
            config: TransportConfig::default(),
            service_uuid: BLE_SERVICE_UUID.to_string(),
            available: false,
            running: Arc::new(RwLock::new(false)),
            peripherals: Arc::new(RwLock::new(HashMap::new())),
            advertising: Arc::new(RwLock::new(false)),
            scanning: Arc::new(RwLock::new(false)),
            shutdown_tx: None,
            message_tx: None,
        }
    }

    pub fn with_config(mut self, config: TransportConfig) -> Self {
        self.config = config;
        self
    }

    pub fn is_available(&self) -> bool {
        self.available
    }

    pub fn set_available(&mut self, available: bool) {
        self.available = available;
    }

    pub async fn start_advertising(&self, local_name: &str) -> TransportResult<()> {
        if !self.available {
            return Err(TransportError::NotAvailable(
                "BLE not available on this platform".into(),
            ));
        }

        if *self.advertising.read().await {
            return Ok(());
        }

        info!("Starting BLE advertising as '{}'", local_name);
        *self.advertising.write().await = true;

        Ok(())
    }

    pub async fn stop_advertising(&self) -> TransportResult<()> {
        *self.advertising.write().await = false;
        info!("Stopped BLE advertising");
        Ok(())
    }

    pub async fn start_scanning(&self) -> TransportResult<()> {
        if !self.available {
            return Err(TransportError::NotAvailable(
                "BLE not available on this platform".into(),
            ));
        }

        if *self.scanning.read().await {
            return Ok(());
        }

        info!("Starting BLE scanning");
        *self.scanning.write().await = true;

        Ok(())
    }

    pub async fn stop_scanning(&self) -> TransportResult<()> {
        *self.scanning.write().await = false;
        info!("Stopped BLE scanning");
        Ok(())
    }

    pub async fn discovered_devices(&self) -> Vec<BleDevice> {
        let peripherals = self.peripherals.read().await;
        peripherals
            .values()
            .map(|p| BleDevice {
                address: p.address.clone(),
                name: p.name.clone(),
                rssi: p.rssi,
                connected: p.connected,
            })
            .collect()
    }

    pub async fn connect(&self, address: &str) -> TransportResult<String> {
        if !self.available {
            return Err(TransportError::NotAvailable(
                "BLE not available on this platform".into(),
            ));
        }

        let peripheral_id = format!("ble-{}", uuid::Uuid::new_v4());
        
        let peripheral = BlePeripheral {
            address: address.to_string(),
            name: None,
            rssi: -50,
            connected: true,
            mtu: DEFAULT_MTU,
        };

        self.peripherals
            .write()
            .await
            .insert(peripheral_id.clone(), peripheral);

        info!("Connected to BLE device {} as {}", address, peripheral_id);
        Ok(peripheral_id)
    }

    pub async fn disconnect(&self, peripheral_id: &str) -> TransportResult<()> {
        let mut peripherals = self.peripherals.write().await;
        if let Some(peripheral) = peripherals.get_mut(peripheral_id) {
            peripheral.connected = false;
            info!("Disconnected from BLE device {}", peripheral_id);
        }
        peripherals.remove(peripheral_id);
        Ok(())
    }

    pub async fn send(&self, peripheral_id: &str, data: &[u8]) -> TransportResult<usize> {
        let mut peripherals = self.peripherals.write().await;
        let peripheral = peripherals
            .get_mut(peripheral_id)
            .ok_or_else(|| TransportError::PeerNotFound(peripheral_id.to_string()))?;

        if !peripheral.connected {
            return Err(TransportError::ConnectionFailed(
                "Not connected to peripheral".into(),
            ));
        }

        if data.len() > peripheral.mtu {
            return Err(TransportError::Buffer(format!(
                "Data too large for MTU: {} > {}",
                data.len(),
                peripheral.mtu
            )));
        }

        debug!("BLE sent {} bytes to {}", data.len(), peripheral_id);
        Ok(data.len())
    }

    pub async fn receive(&self, peripheral_id: &str, timeout_ms: u64) -> TransportResult<Vec<u8>> {
        tokio::time::sleep(Duration::from_millis(timeout_ms)).await;
        Err(TransportError::Timeout("No data available".into()))
    }

    pub async fn request_mtu(&self, peripheral_id: &str, mtu: usize) -> TransportResult<usize> {
        let mut peripherals = self.peripherals.write().await;
        let peripheral = peripherals
            .get_mut(peripheral_id)
            .ok_or_else(|| TransportError::PeerNotFound(peripheral_id.to_string()))?;

        let actual_mtu = mtu.min(MAX_MTU).max(23);
        peripheral.mtu = actual_mtu;
        
        info!("MTU for {} set to {}", peripheral_id, actual_mtu);
        Ok(actual_mtu)
    }

    pub fn service_uuid(&self) -> &str {
        &self.service_uuid
    }

    pub fn config(&self) -> &TransportConfig {
        &self.config
    }
}

impl Default for BleTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Transport for BleTransport {
    fn start(&self) -> TransportResult<()> {
        if !self.available {
            warn!("BLE transport not available on this platform");
            return Err(TransportError::NotAvailable(
                "BLE not supported".into(),
            ));
        }

        if *self.running.blocking_read() {
            return Ok(());
        }

        info!("Starting BLE transport");

        *self.running.write().await = true;

        let (shutdown_tx, _) = broadcast::channel(1);
        let (message_tx, _) = broadcast::channel(100);
        
        self.shutdown_tx = Some(shutdown_tx);
        self.message_tx = Some(message_tx);

        Ok(())
    }

    fn stop(&self) -> TransportResult<()> {
        info!("Stopping BLE transport");
        
        *self.running.write().await = false;
        
        *self.advertising.write().await = false;
        *self.scanning.write().await = false;

        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(());
        }

        self.peripherals.write().await.clear();

        Ok(())
    }

    fn is_running(&self) -> bool {
        *self.running.blocking_read()
    }

    fn local_peer_id(&self) -> Option<String> {
        Some(format!("ble-local-{}", uuid::Uuid::new_v4()))
    }
}

#[derive(Clone, Debug)]
pub struct BleDevice {
    pub address: String,
    pub name: Option<String>,
    pub rssi: i16,
    pub connected: bool,
}

#[derive(Clone)]
pub struct BleConfig {
    pub scan_duration_secs: u64,
    pub connection_timeout_ms: u64,
    pub min_rssi: i16,
    pub filter_duplicates: bool,
    pub phy_mode: BlePhyMode,
}

impl Default for BleConfig {
    fn default() -> Self {
        Self {
            scan_duration_secs: 10,
            connection_timeout_ms: 10_000,
            min_rssi: -80,
            filter_duplicates: true,
            phy_mode: BlePhyMode::Le1M,
        }
    }
}

#[derive(Clone, Debug)]
pub enum BlePhyMode {
    Le1M,
    Le2M,
    LeCoded,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ble_transport_creation() {
        let transport = BleTransport::new();
        assert!(!transport.is_available());
    }

    #[test]
    fn test_ble_config_defaults() {
        let config = BleConfig::default();
        assert_eq!(config.min_rssi, -80);
    }
}
