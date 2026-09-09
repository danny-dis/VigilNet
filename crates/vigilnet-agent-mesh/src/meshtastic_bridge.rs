use crate::mesh_fallback::MeshError;
use crate::mesh_fallback::MeshResult;
use anyhow::Result as AnyhowResult;
use bytes::Bytes;
use futures::StreamExt;
use parking_lot::RwLock;
use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, instrument, warn};

#[derive(Debug, Clone)]
pub struct MeshtasticConfig {
    pub mqtt_broker: String,
    pub mqtt_port: u16,
    pub username: Option<String>,
    password: Option<String>,
    pub root_topic: String,
    pub device_id: String,
    pub use_tls: bool,
    pub reconnect_interval_secs: u64,
    pub keep_alive_secs: u16,
}

impl Default for MeshtasticConfig {
    fn default() -> Self {
        Self {
            mqtt_broker: "mqtt.meshtastic.org".to_string(),
            mqtt_port: 1883,
            username: None,
            password: None,
            root_topic: "msh".to_string(),
            device_id: uuid::Uuid::new_v4().to_string()[..8].to_string(),
            use_tls: false,
            reconnect_interval_secs: 5,
            keep_alive_secs: 60,
        }
    }
}

impl MeshtasticConfig {
    pub fn new(
        mqtt_broker: impl Into<String>,
        root_topic: impl Into<String>,
        device_id: impl Into<String>,
    ) -> Self {
        Self {
            mqtt_broker: mqtt_broker.into(),
            root_topic: root_topic.into(),
            device_id: device_id.into(),
            ..Default::default()
        }
    }

    pub fn with_credentials(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }

    pub fn with_tls(mut self) -> Self {
        self.use_tls = true;
        self.mqtt_port = 8883;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshtasticMessage {
    #[serde(rename = "from")]
    pub from_node: u32,
    #[serde(rename = "to")]
    pub to_node: u32,
    pub payload: Vec<u8>,
    pub channel: u8,
    pub hop_limit: u8,
    pub priority: u8,
    pub timestamp: u64,
    pub message_id: u32,
}

impl MeshtasticMessage {
    pub fn new(from_node: u32, to_node: u32, payload: Vec<u8>) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let message_id = rand::random();

        Self {
            from_node,
            to_node,
            payload,
            channel: 0,
            hop_limit: 3,
            priority: 0,
            timestamp,
            message_id,
        }
    }

    pub fn to_mqtt_payload(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    pub fn from_mqtt_payload(data: &[u8]) -> Option<Self> {
        serde_json::from_slice(data).ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshtasticDeviceInfo {
    pub node_id: u32,
    pub user: Option<MeshtasticUser>,
    pub position: Option<MeshtasticPosition>,
    pub last_heard: u64,
    pub num_channels: u32,
    pub model: String,
    pub firmware_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshtasticUser {
    pub id: String,
    pub long_name: String,
    pub short_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshtasticPosition {
    pub latitude: f64,
    pub longitude: f64,
    pub altitude: i32,
    pub time: u64,
}

pub struct MeshtasticBridge {
    config: MeshtasticConfig,
    client: Option<AsyncClient>,
    event_loop: Option<rumqttc::EventLoop>,
    connected: Arc<RwLock<bool>>,
    subscribed_topics: Arc<RwLock<Vec<String>>>,
    message_sender: Option<mpsc::Sender<MeshtasticMessage>>,
    message_receiver: Arc<RwLock<Option<mpsc::Receiver<MeshtasticMessage>>>>,
    node_cache: Arc<RwLock<HashMap<u32, MeshtasticDeviceInfo>>>,
}

impl MeshtasticBridge {
    #[instrument(skip_all, name = "MeshtasticBridge::new")]
    pub fn new(config: MeshtasticConfig) -> AnyhowResult<Self> {
        let (tx, rx) = mpsc::channel(100);

        info!(
            broker = %config.mqtt_broker,
            port = %config.mqtt_port,
            root_topic = %config.root_topic,
            "Meshtastic bridge created"
        );

        Ok(Self {
            config,
            client: None,
            event_loop: None,
            connected: Arc::new(RwLock::new(false)),
            subscribed_topics: Arc::new(RwLock::new(Vec::new())),
            message_sender: Some(tx),
            message_receiver: Arc::new(RwLock::new(Some(rx))),
            node_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    #[instrument(skip(self))]
    pub async fn connect(&self) -> MeshResult<()> {
        let mut mqtt_options = MqttOptions::new(
            &format!("vigilnet-{}", self.config.device_id),
            &self.config.mqtt_broker,
            self.config.mqtt_port,
        );

        mqtt_options.set_keep_alive(self.config.keep_alive_secs);

        if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            mqtt_options.set_credentials(username, password);
        }

        let (client, event_loop) = AsyncClient::new(mqtt_options, 100);
        
        self.client = Some(client.clone());
        self.event_loop = Some(event_loop);

        self.subscribe_to_topics(&client).await?;

        *self.connected.write() = true;

        info!("Connected to Meshtastic MQTT broker");

        Ok(())
    }

    async fn subscribe_to_topics(&self, client: &AsyncClient) -> MeshResult<()> {
        let topics = vec![
            format!("{}/+/json", self.config.root_topic),
            format!("{}/+/channel/+/json", self.config.root_topic),
            format!("{}/+/telemetry", self.config.root_topic),
        ];

        for topic in &topics {
            client
                .subscribe(topic, QoS::AtLeastOnce)
                .await
                .map_err(|e| MeshError::MeshtasticError(e.to_string()))?;
            
            debug!(topic = %topic, "Subscribed to topic");
        }

        *self.subscribed_topics.write() = topics;

        Ok(())
    }

    pub async fn disconnect(&self) -> MeshResult<()> {
        if let Some(ref client) = self.client {
            client.close();
        }

        *self.connected.write() = false;

        info!("Disconnected from Meshtastic MQTT broker");

        Ok(())
    }

    pub async fn publish(&self, destination: &str, payload: &[u8]) -> MeshResult<()> {
        if !*self.connected.read() {
            return Err(MeshError::MeshtasticError("Not connected".to_string()));
        }

        let client = self.client.as_ref()
            .ok_or_else(|| MeshError::MeshtasticError("Client not initialized".to_string()))?;

        let to_node: u32 = destination.parse()
            .unwrap_or(0xffffffff);

        let message = MeshtasticMessage::new(
            0,
            to_node,
            payload.to_vec(),
        );

        let topic = format!("{}/2/json", self.config.root_topic);
        
        let payload = message.to_mqtt_payload();

        client
            .publish(topic, QoS::AtLeastOnce, false, payload)
            .await
            .map_err(|e| MeshError::MeshtasticError(e.to_string()))?;

        debug!(dest = %destination, bytes = %payload.len(), "Published to Meshtastic");

        Ok(())
    }

    pub async fn publish_text(&self, destination: &str, text: &str) -> MeshResult<()> {
        self.publish(destination, text.as_bytes()).await
    }

    pub async fn broadcast(&self, payload: &[u8]) -> MeshResult<()> {
        self.publish("broadcast", payload).await
    }

    pub async fn start_listener(&mut self) -> MeshResult<()> {
        let event_loop = self.event_loop.take()
            .ok_or_else(|| MeshError::MeshtasticError("Event loop not initialized".to_string()))?;

        let sender = self.message_sender.take()
            .ok_or_else(|| MeshError::MeshtasticError("Sender not initialized".to_string()))?;

        let root_topic = self.config.root_topic.clone();
        let node_cache = self.node_cache.clone();

        tokio::spawn(async move {
            let mut event_loop = event_loop;
            
            loop {
                match event_loop.poll().await {
                    Ok(notification) => {
                        if let Event::Incoming(Packet::Publish(publish)) = notification {
                            if let Some(message) = Self::parse_mqtt_message(&publish.topic, &publish.payload) {
                                if sender.send(message).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "MQTT error");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        });

        info!("Started Meshtastic message listener");

        Ok(())
    }

    fn parse_mqtt_message(topic: &str, payload: &[u8]) -> Option<MeshtasticMessage> {
        if topic.contains("/json") {
            MeshtasticMessage::from_mqtt_payload(payload)
        } else {
            None
        }
    }

    pub async fn receive(&self) -> Option<MeshtasticMessage> {
        let mut receiver = self.message_receiver.write();
        if let Some(ref mut rx) = *receiver {
            rx.recv().await
        } else {
            None
        }
    }

    pub fn is_connected(&self) -> bool {
        *self.connected.read()
    }

    pub fn get_subscribed_topics(&self) -> Vec<String> {
        self.subscribed_topics.read().clone()
    }

    pub fn get_node_info(&self, node_id: u32) -> Option<MeshtasticDeviceInfo> {
        self.node_cache.read().get(&node_id).cloned()
    }

    pub fn get_all_nodes(&self) -> Vec<MeshtasticDeviceInfo> {
        self.node_cache.read().values().cloned().collect()
    }
}

pub struct MeshtasticRouter {
    bridge: Arc<MeshtasticBridge>,
    routes: Arc<RwLock<HashMap<String, Vec<u32>>>>,
}

impl MeshtasticRouter {
    pub fn new(bridge: Arc<MeshtasticBridge>) -> Self {
        Self {
            bridge,
            routes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn route_message(&self, message: MeshtasticMessage) -> MeshResult<()> {
        let to_node = message.to_node;

        if to_node == 0xffffffff {
            self.bridge.broadcast(&message.payload).await?;
        } else {
            self.bridge.publish(&to_node.to_string(), &message.payload).await?;
        }

        Ok(())
    }

    pub fn add_route(&self, destination: String, via_nodes: Vec<u32>) {
        let mut routes = self.routes.write();
        routes.insert(destination, via_nodes);
    }

    pub fn get_route(&self, destination: &str) -> Option<Vec<u32>> {
        let routes = self.routes.read();
        routes.get(destination).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_meshtastic_config_defaults() {
        let config = MeshtasticConfig::default();
        assert_eq!(config.mqtt_broker, "mqtt.meshtastic.org");
        assert_eq!(config.mqtt_port, 1883);
    }

    #[test]
    fn test_meshtastic_config_builder() {
        let config = MeshtasticConfig::new("custom.meshtastic.org", "custom", "device123")
            .with_credentials("user", "pass")
            .with_tls();

        assert_eq!(config.mqtt_broker, "custom.meshtastic.org");
        assert_eq!(config.use_tls, true);
        assert_eq!(config.mqtt_port, 8883);
    }

    #[tokio::test]
    async fn test_bridge_creation() -> AnyhowResult<()> {
        let config = MeshtasticConfig::default();
        let _bridge = MeshtasticBridge::new(config)?;
        Ok(())
    }
}
