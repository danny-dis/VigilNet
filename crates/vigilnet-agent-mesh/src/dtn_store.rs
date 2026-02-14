use crate::mesh_fallback::MeshError;
use crate::mesh_fallback::MeshResult;
use anyhow::Result as AnyhowResult;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, instrument, warn};

#[derive(Debug, Clone)]
pub struct DtnStoreConfig {
    pub store_path: PathBuf,
    pub max_messages: usize,
    pub max_size_bytes: u64,
    pub cleanup_interval_secs: u64,
    pub message_ttl_secs: u64,
    pub retry_initial_delay_ms: u64,
    pub retry_max_delay_ms: u64,
    pub max_retry_attempts: u32,
}

impl Default for DtnStoreConfig {
    fn default() -> Self {
        let store_path = directories::ProjectDirs::from("com", "vigilnet", "agent")
            .map(|dirs| dirs.data_dir().join("dtn_store"))
            .unwrap_or_else(|| PathBuf::from("./dtn_store"));

        Self {
            store_path,
            max_messages: 10000,
            max_size_bytes: 100 * 1024 * 1024,
            cleanup_interval_secs: 3600,
            message_ttl_secs: 86400,
            retry_initial_delay_ms: 1000,
            retry_max_delay_ms: 300000,
            max_retry_attempts: 5,
        }
    }
}

impl DtnStoreConfig {
    pub fn new(store_path: PathBuf) -> Self {
        Self {
            store_path,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtnMessage {
    pub id: String,
    pub payload: Vec<u8>,
    pub destination: String,
    pub source: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub retry_count: u32,
    pub priority: u8,
    pub status: DtnMessageStatus,
    pub metadata: DtnMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DtnMessageStatus {
    Pending,
    InTransit,
    Delivered,
    Failed,
    Expired,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DtnMetadata {
    pub original_size: usize,
    pub compressed: bool,
    pub encryption: Option<String>,
    pub routing_info: Option<String>,
}

impl DtnMessage {
    pub fn new(payload: Vec<u8>, destination: String, source: String) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let created_at = Utc::now();
        let expires_at = created_at + chrono::Duration::seconds(86400);

        Self {
            id,
            payload,
            destination,
            source,
            created_at,
            expires_at,
            retry_count: 0,
            priority: 0,
            status: DtnMessageStatus::Pending,
            metadata: DtnMetadata::default(),
        }
    }

    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_ttl(mut self, ttl_secs: i64) -> Self {
        self.expires_at = self.created_at + chrono::Duration::seconds(ttl_secs);
        self
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn increment_retry(&mut self) {
        self.retry_count += 1;
    }

    pub fn calculate_backoff(&self, initial_delay_ms: u64, max_delay_ms: u64) -> Duration {
        let delay = initial_delay_ms * (2_u64.pow(self.retry_count.min(10)));
        let delay = delay.min(max_delay_ms);
        Duration::from_millis(delay)
    }
}

pub struct DtnStore {
    config: DtnStoreConfig,
    messages: Arc<RwLock<VecDeque<DtnMessage>>>,
    pending_retry: Arc<RwLock<VecDeque<DtnMessage>>>,
    index: Arc<RwLock<HashMap<String, usize>>>,
    total_size: Arc<RwLock<u64>>,
    shutdown_flag: Arc<RwLock<bool>>,
}

impl DtnStore {
    #[instrument(skip_all, name = "DtnStore::new")]
    pub fn new(config: DtnStoreConfig) -> AnyhowResult<Self> {
        let store_path = config.store_path.clone();
        
        if !store_path.exists() {
            fs::create_dir_all(&store_path)?;
        }

        let index_path = store_path.join("index.bin");
        let messages_path = store_path.join("messages.bin");

        let (messages, index, total_size) = if index_path.exists() && messages_path.exists() {
            Self::load_existing(&store_path)?
        } else {
            (VecDeque::new(), HashMap::new(), 0u64)
        };

        info!(
            path = %store_path.display(),
            messages = %messages.len(),
            "DTN store initialized"
        );

        Ok(Self {
            config,
            messages: Arc::new(RwLock::new(messages)),
            pending_retry: Arc::new(RwLock::new(VecDeque::new())),
            index: Arc::new(RwLock::new(index)),
            total_size: Arc::new(RwLock::new(total_size)),
            shutdown_flag: Arc::new(RwLock::new(false)),
        })
    }

    fn load_existing(store_path: &PathBuf) -> AnyhowResult<(VecDeque<DtnMessage>, HashMap<String, usize>, u64)> {
        let index_path = store_path.join("index.bin");
        let messages_path = store_path.join("messages.bin");

        let index_file = File::open(&index_path)?;
        let messages_file = File::open(&messages_path)?;

        let mut index_reader = BufReader::new(index_file);
        let mut index = HashMap::new();
        
        let mut index_data = Vec::new();
        index_reader.read_to_end(&mut index_data)?;
        
        let ids: Vec<String> = bincode::deserialize(&index_data)?;
        for (i, id) in ids.iter().enumerate() {
            index.insert(id.clone(), i);
        }

        let mut messages_reader = BufReader::new(messages_file);
        let mut messages_data = Vec::new();
        messages_reader.read_to_end(&mut messages_data)?;
        
        let messages: Vec<DtnMessage> = bincode::deserialize(&messages_data)?;
        let total_size = messages_data.len() as u64;

        Ok((VecDeque::from(messages), index, total_size))
    }

    pub fn store(&self, payload: &[u8], destination: &str) -> MeshResult<String> {
        if *self.shutdown_flag.read() {
            return Err(MeshError::DtnError("Store is shutting down".to_string()));
        }

        let message = DtnMessage::new(
            payload.to_vec(),
            destination.to_string(),
            String::new(),
        );

        let message_id = message.id.clone();
        let message_size = payload.len() as u64;

        {
            let mut total = self.total_size.write();
            *total += message_size;
        }

        {
            let mut messages = self.messages.write();
            let mut index = self.index.write();

            if messages.len() >= self.config.max_messages {
                self.evict_oldest(&mut messages, &mut index);
            }

            let pos = messages.len();
            messages.push_back(message);
            index.insert(message_id.clone(), pos);
        }

        debug!(
            id = %message_id,
            dest = %destination,
            size = message_size,
            "Message stored in DTN"
        );

        Ok(message_id)
    }

    fn evict_oldest(&self, messages: &mut VecDeque<DtnMessage>, index: &mut HashMap<String, usize>) {
        if let Some(evicted) = messages.pop_front() {
            index.remove(&evicted.id);
            
            let mut size = self.total_size.write();
            *size = size.saturating_sub(evicted.payload.len() as u64);

            for (i, msg) in messages.iter().enumerate() {
                index.insert(msg.id.clone(), i);
            }

            warn!(id = %evicted.id, "Evicted old message from store");
        }
    }

    pub fn retrieve(&self, message_id: &str) -> Option<DtnMessage> {
        let index = self.index.read();
        let messages = self.messages.read();

        if let Some(&pos) = index.get(message_id) {
            messages.get(pos).cloned()
        } else {
            None
        }
    }

    pub fn delete(&self, message_id: &str) -> MeshResult<()> {
        let mut messages = self.messages.write();
        let mut index = self.index.write();

        if let Some(&pos) = index.get(message_id) {
            if let Some(msg) = messages.remove(pos) {
                let mut total = self.total_size.write();
                *total = total.saturating_sub(msg.payload.len() as u64);
            }

            index.remove(message_id);

            for (i, msg) in messages.iter().enumerate() {
                index.insert(msg.id.clone(), i);
            }

            debug!(id = %message_id, "Message deleted from store");
        }

        Ok(())
    }

    pub fn update_status(&self, message_id: &str, status: DtnMessageStatus) -> MeshResult<()> {
        let mut messages = self.messages.write();
        
        if let Some(msg) = messages.iter_mut().find(|m| m.id == message_id) {
            msg.status = status;
            debug!(id = %message_id, status = ?status, "Message status updated");
        }

        Ok(())
    }

    pub fn get_pending_messages(&self) -> Vec<DtnMessage> {
        let messages = self.messages.read();
        
        messages
            .iter()
            .filter(|m| m.status == DtnMessageStatus::Pending)
            .cloned()
            .collect()
    }

    pub fn get_messages_for_destination(&self, destination: &str) -> Vec<DtnMessage> {
        let messages = self.messages.read();
        
        messages
            .iter()
            .filter(|m| m.destination == destination && m.status == DtnMessageStatus::Pending)
            .cloned()
            .collect()
    }

    pub fn get_all_messages(&self) -> Vec<DtnMessage> {
        self.messages.read().iter().cloned().collect()
    }

    pub fn get_message_count(&self) -> usize {
        self.messages.read().len()
    }

    pub fn get_total_size(&self) -> u64 {
        *self.total_size.read()
    }

    pub fn flush(&self) -> AnyhowResult<()> {
        let store_path = &self.config.store_path;
        let index_path = store_path.join("index.bin");
        let messages_path = store_path.join("messages.bin");

        let messages = self.messages.read();
        let ids: Vec<String> = messages.iter().map(|m| m.id.clone()).collect();

        let index_data = bincode::serialize(&ids)?;
        let messages_data = bincode::serialize(&**messages)?;

        let mut index_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(index_path)?;
        
        let mut messages_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(messages_path)?;

        index_file.write_all(&index_data)?;
        messages_file.write_all(&messages_data)?;

        info!(
            messages = %messages.len(),
            "Flushed DTN store to disk"
        );

        Ok(())
    }

    pub async fn start_cleanup_task(&self) -> AnyhowResult<()> {
        let messages = Arc::clone(&self.messages);
        let index = Arc::clone(&self.index);
        let total_size = Arc::clone(&self.total_size);
        let config = self.config.clone();
        let shutdown = Arc::clone(&self.shutdown_flag);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(config.cleanup_interval_secs));
            
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if *shutdown.read() {
                            break;
                        }
                        
                        Self::cleanup_expired(&messages, &index, &total_size, &config).await;
                    }
                }
            }
        });

        Ok(())
    }

    async fn cleanup_expired(
        messages: &Arc<RwLock<VecDeque<DtnMessage>>>,
        index: &Arc<RwLock<HashMap<String, usize>>>,
        total_size: &Arc<RwLock<u64>>,
        config: &DtnStoreConfig,
    ) {
        let mut to_delete = Vec::new();
        
        {
            let msgs = messages.read();
            for msg in msgs.iter() {
                if msg.is_expired() {
                    to_delete.push(msg.id.clone());
                }
            }
        }

        for id in to_delete {
            let mut msgs = messages.write();
            let mut idx = index.write();
            
            if let Some(pos) = idx.get(&id) {
                if let Some(msg) = msgs.remove(*pos) {
                    let mut size = total_size.write();
                    *size = size.saturating_sub(msg.payload.len() as u64);
                }
                
                idx.remove(&id);
                
                for (i, m) in msgs.iter().enumerate() {
                    idx.insert(m.id.clone(), i);
                }
            }
        }

        debug!(removed = %to_delete.len(), "Cleaned up expired messages");
    }

    pub fn shutdown(&self) {
        *self.shutdown_flag.write() = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_dtn_message_creation() {
        let msg = DtnMessage::new(
            b"test payload".to_vec(),
            "destination".to_string(),
            "source".to_string(),
        );

        assert!(!msg.is_expired());
        assert_eq!(msg.status, DtnMessageStatus::Pending);
    }

    #[test]
    fn test_dtn_message_backoff() {
        let mut msg = DtnMessage::new(
            b"test".to_vec(),
            "dest".to_string(),
            "source".to_string(),
        );

        msg.retry_count = 0;
        let delay1 = msg.calculate_backoff(1000, 300000);
        
        msg.retry_count = 1;
        let delay2 = msg.calculate_backoff(1000, 300000);
        
        msg.retry_count = 5;
        let delay5 = msg.calculate_backoff(1000, 300000);

        assert!(delay2 > delay1);
        assert!(delay5 > delay2);
    }

    #[tokio::test]
    async fn test_dtn_store_creation() -> AnyhowResult<()> {
        let temp_dir = tempdir()?;
        let config = DtnStoreConfig::new(temp_dir.path().to_path_buf());
        
        let store = DtnStore::new(config)?;
        
        assert_eq!(store.get_message_count(), 0);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_dtn_store_operations() -> AnyhowResult<()> {
        let temp_dir = tempdir()?;
        let config = DtnStoreConfig::new(temp_dir.path().to_path_buf());
        
        let store = DtnStore::new(config)?;
        
        let id = store.store(b"hello world", "recipient1")?;
        assert_eq!(store.get_message_count(), 1);
        
        let retrieved = store.retrieve(&id);
        assert!(retrieved.is_some());
        
        store.delete(&id)?;
        assert_eq!(store.get_message_count(), 0);
        
        Ok(())
    }
}
