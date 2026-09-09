//! Binary message protocol for VigilNet agent communication

use bincode::{config, Decode, Encode};
use serde::{Deserialize, Serialize};
use vigilnet_crypto::{Session, SessionMessage};

/// Message flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub struct MessageFlags(pub u8);

impl MessageFlags {
    pub const NONE: Self = Self(0b0000_0000);
    pub const ENCRYPTED: Self = Self(0b0000_0001);
    pub const BATCHED: Self = Self(0b0000_0010);
    pub const PRIORITY: Self = Self(0b0000_0100);
    pub const ACK: Self = Self(0b0000_1000);
    pub const HEARTBEAT: Self = Self(0b0001_0000);

    pub fn is_encrypted(&self) -> bool {
        self.0 & Self::ENCRYPTED.0 != 0
    }

    pub fn set_encrypted(&mut self) {
        self.0 |= Self::ENCRYPTED.0;
    }

    pub fn is_batched(&self) -> bool {
        self.0 & Self::BATCHED.0 != 0
    }

    pub fn set_batched(&mut self) {
        self.0 |= Self::BATCHED.0;
    }
}

/// Fixed-size header: flags(1) + sender(8) + seq(4) + topic(4) + len(2) = 19 bytes
#[derive(Debug, Clone, Encode, Decode)]
pub struct MessageHeader {
    pub flags: MessageFlags,
    pub sender: [u8; 8],
    pub sequence: u32,
    pub topic: u32,
    pub length: u16,
}

impl MessageHeader {
    pub const SIZE: usize = 19;

    pub fn new(sender: [u8; 8], sequence: u32, topic: u32, length: u16) -> Self {
        Self {
            flags: MessageFlags::NONE,
            sender,
            sequence,
            topic,
            length,
        }
    }

    pub fn with_flags(mut self, flags: MessageFlags) -> Self {
        self.flags = flags;
        self
    }

    pub fn total_size(&self) -> usize {
        Self::SIZE + self.length as usize
    }
}

/// Message types
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub enum MessageType {
    Data,
    Request,
    Response,
    Discovery,
    Heartbeat,
    Ack,
    Nak,
}

/// Complete message with header and payload
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Message {
    pub header: MessageHeader,
    pub payload: Vec<u8>,
    pub msg_type: MessageType,
    pub encrypted_payload: Option<EncryptedPayload>,
}

/// Encrypted payload using Signal Protocol
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct EncryptedPayload {
    pub session_id: String,
    pub ciphertext: Vec<u8>,
    pub message_number: u32,
    pub is_prekey_message: bool,
}

impl Message {
    pub fn new(
        sender: [u8; 8],
        sequence: u32,
        topic: u32,
        payload: Vec<u8>,
        msg_type: MessageType,
    ) -> Self {
        let length = payload.len() as u16;
        Self {
            header: MessageHeader::new(sender, sequence, topic, length),
            payload,
            msg_type,
            encrypted_payload: None,
        }
    }

    pub fn with_flags(mut self, flags: MessageFlags) -> Self {
        self.header = self.header.with_flags(flags);
        self
    }

    pub fn total_size(&self) -> usize {
        self.header.total_size()
    }

    pub fn encrypt(&mut self, session: &mut Session) -> Result<(), MessageError> {
        if self.header.flags.is_encrypted() {
            return Ok(());
        }

        let encrypted = session
            .encrypt(&self.payload)
            .map_err(|e| MessageError::EncryptionError(e.to_string()))?;

        self.encrypted_payload = Some(EncryptedPayload {
            session_id: encrypted.session_id.clone(),
            ciphertext: encrypted.payload,
            message_number: session.message_count(),
            is_prekey_message: matches!(
                encrypted.message_type,
                vigilnet_crypto::MessageType::X3DHPreKey { .. }
            ),
        });

        self.payload.clear();
        let mut flags = self.header.flags;
        flags.set_encrypted();
        self.header.flags = flags;

        Ok(())
    }

    pub fn decrypt(&mut self, session: &mut Session) -> Result<(), MessageError> {
        if !self.header.flags.is_encrypted() {
            return Ok(());
        }

        let encrypted = self
            .encrypted_payload
            .as_ref()
            .ok_or_else(|| MessageError::InvalidMessage("Missing encrypted payload".into()))?;

        let session_msg = SessionMessage {
            session_id: encrypted.session_id.clone(),
            message_type: vigilnet_crypto::MessageType::RatchetMessage(
                vigilnet_crypto::EncryptedMessage {
                    header: vigilnet_crypto::MessageHeader {
                        previous_chain_length: 0,
                        message_number: encrypted.message_number,
                        public_key: None,
                    },
                    ciphertext: encrypted.ciphertext.clone(),
                },
            ),
            payload: encrypted.ciphertext.clone(),
        };

        self.payload = session
            .decrypt(&session_msg)
            .map_err(|e| MessageError::DecryptionError(e.to_string()))?;

        let mut flags = self.header.flags;
        flags.0 &= !MessageFlags::ENCRYPTED.0;
        self.header.flags = flags;
        self.encrypted_payload = None;

        Ok(())
    }
}

/// Batched messages for efficient transmission
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct MessageBatch {
    pub messages: Vec<Message>,
    pub batch_id: [u8; 8],
    pub timestamp: i64,
}

impl MessageBatch {
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            batch_id: uuid::Uuid::new_v4().as_bytes(),
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    pub fn push(&mut self, message: Message) {
        self.messages.push(message);
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn total_size(&self) -> usize {
        self.messages.iter().map(|m| m.total_size()).sum()
    }

    pub fn into_messages(self) -> Vec<Message> {
        self.messages
    }
}

impl Default for MessageBatch {
    fn default() -> Self {
        Self::new()
    }
}

/// Message serializer using bincode
pub struct MessageSerializer {
    config: config::Configuration,
}

impl MessageSerializer {
    pub fn new() -> Self {
        Self {
            config: bincode::config::standard()
                .with_little_endian()
                .with_fixed_int_encoding(),
        }
    }

    pub fn serialize<T: Encode>(&self, value: &T) -> Result<Vec<u8>, MessageError> {
        bincode::encode_to_vec(value, self.config)
            .map_err(|e| MessageError::SerializationError(e.to_string()))
    }

    pub fn deserialize<T: Decode>(&self, data: &[u8]) -> Result<T, MessageError> {
        bincode::decode_from_slice(data, self.config)
            .map(|(t, _)| t)
            .map_err(|e| MessageError::DeserializationError(e.to_string()))
    }

    pub fn serialize_message(&self, msg: &Message) -> Result<Vec<u8>, MessageError> {
        self.serialize(msg)
    }

    pub fn deserialize_message(&self, data: &[u8]) -> Result<Message, MessageError> {
        self.deserialize(data)
    }

    pub fn serialize_batch(&self, batch: &MessageBatch) -> Result<Vec<u8>, MessageError> {
        self.serialize(batch)
    }

    pub fn deserialize_batch(&self, data: &[u8]) -> Result<MessageBatch, MessageError> {
        self.deserialize(data)
    }
}

impl Default for MessageSerializer {
    fn default() -> Self {
        Self::new()
    }
}

/// Message error types
#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Buffer too small: {0}")]
    BufferTooSmall(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),
}

pub type Result<T> = std::result::Result<T, MessageError>;

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================
    // Unit Tests for Core Functionality
    // ============================================

    #[test]
    fn test_message_flags_basic() {
        let flags = MessageFlags::NONE;
        assert!(!flags.is_encrypted());
        assert!(!flags.is_batched());

        let mut flags = MessageFlags::ENCRYPTED;
        assert!(flags.is_encrypted());
        
        flags.set_batched();
        assert!(flags.is_batched());
        assert!(flags.is_encrypted());
    }

    #[test]
    fn test_message_flags_all_variants() {
        let encrypted = MessageFlags::ENCRYPTED;
        assert!(encrypted.is_encrypted());
        
        let batched = MessageFlags::BATCHED;
        assert!(batched.is_batched());
        
        let priority = MessageFlags::PRIORITY;
        assert_eq!(priority.0, 0b0000_0100);
        
        let ack = MessageFlags::ACK;
        assert_eq!(ack.0, 0b0000_1000);
        
        let heartbeat = MessageFlags::HEARTBEAT;
        assert_eq!(heartbeat.0, 0b0001_0000);
    }

    #[test]
    fn test_message_header_creation() {
        let header = MessageHeader::new([1, 2, 3, 4, 5, 6, 7, 8], 100, 50, 1024);
        assert_eq!(header.sender, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(header.sequence, 100);
        assert_eq!(header.topic, 50);
        assert_eq!(header.length, 1024);
        assert_eq!(header.total_size(), MessageHeader::SIZE + 1024);
    }

    #[test]
    fn test_message_header_with_flags() {
        let header = MessageHeader::new([0u8; 8], 1, 1, 100)
            .with_flags(MessageFlags::ENCRYPTED);
        assert!(header.flags.is_encrypted());
    }

    #[test]
    fn test_message_creation() {
        let msg = Message::new(
            [1, 2, 3, 4, 5, 6, 7, 8],
            1,
            100,
            b"Hello, World!".to_vec(),
            MessageType::Data,
        );
        
        assert_eq!(msg.header.sender, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(msg.header.sequence, 1);
        assert_eq!(msg.payload, b"Hello, World!");
        assert_eq!(msg.header.length, 13);
    }

    #[test]
    fn test_message_with_flags() {
        let msg = Message::new(
            [0u8; 8],
            1,
            1,
            vec![1, 2, 3],
            MessageType::Request,
        ).with_flags(MessageFlags::PRIORITY);
        
        assert!(msg.header.flags.0 & MessageFlags::PRIORITY.0 != 0);
    }

    #[test]
    fn test_message_total_size() {
        let payload = vec![0u8; 100];
        let msg = Message::new(
            [0u8; 8],
            1,
            1,
            payload.clone(),
            MessageType::Data,
        );
        assert_eq!(msg.total_size(), MessageHeader::SIZE + payload.len());
    }

    #[test]
    fn test_message_batch_basic() {
        let mut batch = MessageBatch::new();
        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);
        
        batch.push(Message::new([0u8; 8], 1, 1, b"msg1".to_vec(), MessageType::Data));
        batch.push(Message::new([0u8; 8], 2, 1, b"msg2".to_vec(), MessageType::Data));
        
        assert_eq!(batch.len(), 2);
        assert!(!batch.is_empty());
    }

    #[test]
    fn test_message_batch_total_size() {
        let mut batch = MessageBatch::new();
        let msg1 = Message::new([0u8; 8], 1, 1, vec![0u8; 100], MessageType::Data);
        let msg2 = Message::new([0u8; 8], 2, 1, vec![0u8; 200], MessageType::Data);
        
        batch.push(msg1);
        batch.push(msg2);
        
        let expected_size = (MessageHeader::SIZE + 100) + (MessageHeader::SIZE + 200);
        assert_eq!(batch.total_size(), expected_size);
    }

    #[test]
    fn test_message_batch_into_messages() {
        let mut batch = MessageBatch::new();
        batch.push(Message::new([0u8; 8], 1, 1, b"msg1".to_vec(), MessageType::Data));
        
        let messages = batch.into_messages();
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn test_message_batch_default() {
        let batch: MessageBatch = Default::default();
        assert!(batch.is_empty());
        assert_eq!(batch.batch_id.len(), 8);
    }

    #[test]
    fn test_serializer_creation() {
        let serializer = MessageSerializer::new();
        let msg = Message::new([0u8; 8], 1, 1, b"test".to_vec(), MessageType::Data);
        
        let encoded = serializer.serialize_message(&msg).unwrap();
        let decoded = serializer.deserialize_message(&encoded).unwrap();
        
        assert_eq!(msg.header.sequence, decoded.header.sequence);
        assert_eq!(msg.payload, decoded.payload);
    }

    #[test]
    fn test_serializer_batch() {
        let serializer = MessageSerializer::new();
        let mut batch = MessageBatch::new();
        batch.push(Message::new([0u8; 8], 1, 1, b"msg1".to_vec(), MessageType::Data));
        batch.push(Message::new([0u8; 8], 2, 1, b"msg2".to_vec(), MessageType::Data));
        
        let encoded = serializer.serialize_batch(&batch).unwrap();
        let decoded = serializer.deserialize_batch(&encoded).unwrap();
        
        assert_eq!(decoded.len(), 2);
    }

    #[test]
    fn test_serializer_default() {
        let serializer: MessageSerializer = Default::default();
        assert!(serializer.serialize(&1u32).is_ok());
    }

    #[test]
    fn test_encrypted_payload_creation() {
        let payload = EncryptedPayload {
            session_id: "test-session".to_string(),
            ciphertext: vec![1, 2, 3, 4, 5],
            message_number: 42,
            is_prekey_message: true,
        };
        
        assert_eq!(payload.session_id, "test-session");
        assert_eq!(payload.ciphertext, vec![1, 2, 3, 4, 5]);
        assert_eq!(payload.message_number, 42);
        assert!(payload.is_prekey_message);
    }

    // ============================================
    // Integration Tests
    // ============================================

    #[test]
    fn test_full_message_lifecycle() {
        let serializer = MessageSerializer::new();
        
        // Create a batch of messages
        let mut batch = MessageBatch::new();
        for i in 0..5 {
            let msg = Message::new(
                [i as u8; 8],
                i as u32,
                100,
                format!("message {}", i).into_bytes(),
                MessageType::Data,
            );
            batch.push(msg);
        }
        
        // Serialize
        let encoded = serializer.serialize_batch(&batch).unwrap();
        
        // Deserialize
        let decoded = serializer.deserialize_batch(&encoded).unwrap();
        
        // Verify
        assert_eq!(decoded.len(), 5);
        for (i, msg) in decoded.messages.iter().enumerate() {
            assert_eq!(msg.header.sequence, i as u32);
        }
    }

    #[test]
    fn test_message_type_variants() {
        let types = vec![
            MessageType::Data,
            MessageType::Request,
            MessageType::Response,
            MessageType::Discovery,
            MessageType::Heartbeat,
            MessageType::Ack,
            MessageType::Nak,
        ];
        
        let serializer = MessageSerializer::new();
        
        for (i, msg_type) in types.iter().enumerate() {
            let msg = Message::new([0u8; 8], i as u32, 1, vec![], msg_type.clone());
            let encoded = serializer.serialize_message(&msg).unwrap();
            let decoded = serializer.deserialize_message(&encoded).unwrap();
            
            // Verify the message type matches (can't directly compare enums with bincode)
            assert_eq!(msg.msg_type as i32, decoded.msg_type as i32);
        }
    }

    #[test]
    fn test_large_payload_serialization() {
        let serializer = MessageSerializer::new();
        let large_payload = vec![0u8; 1024 * 1024]; // 1MB payload
        
        let msg = Message::new([0u8; 8], 1, 1, large_payload.clone(), MessageType::Data);
        let encoded = serializer.serialize_message(&msg).unwrap();
        let decoded = serializer.deserialize_message(&encoded).unwrap();
        
        assert_eq!(decoded.payload, large_payload);
    }

    #[test]
    fn test_multiple_batches() {
        let serializer = MessageSerializer::new();
        let mut batches: Vec<MessageBatch> = Vec::new();
        
        for batch_idx in 0..3 {
            let mut batch = MessageBatch::new();
            for msg_idx in 0..5 {
                let msg = Message::new(
                    [batch_idx as u8; 8],
                    msg_idx as u32,
                    batch_idx as u32,
                    format!("batch {} msg {}", batch_idx, msg_idx).into_bytes(),
                    MessageType::Data,
                );
                batch.push(msg);
            }
            batches.push(batch);
        }
        
        // Serialize all batches
        let encoded_batches: Vec<_> = batches.iter()
            .map(|b| serializer.serialize_batch(b).unwrap())
            .collect();
        
        // Deserialize and verify
        for (i, encoded) in encoded_batches.iter().enumerate() {
            let decoded = serializer.deserialize_batch(encoded).unwrap();
            assert_eq!(decoded.len(), 5);
            assert_eq!(decoded.messages[0].header.topic, i as u32);
        }
    }

    // ============================================
    // Error Handling Tests
    // ============================================

    #[test]
    fn test_deserialize_empty_data() {
        let serializer = MessageSerializer::new();
        let result: Result<Message, _> = serializer.deserialize_message(b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_corrupted_data() {
        let serializer = MessageSerializer::new();
        let msg = Message::new([0u8; 8], 1, 1, b"test".to_vec(), MessageType::Data);
        let mut encoded = serializer.serialize_message(&msg).unwrap();
        
        // Corrupt the data
        if !encoded.is_empty() {
            encoded[0] = !encoded[0];
        }
        
        let result: Result<Message, _> = serializer.deserialize_message(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_truncated_data() {
        let serializer = MessageSerializer::new();
        let msg = Message::new([0u8; 8], 1, 1, vec![0u8; 1000], MessageType::Data);
        let encoded = serializer.serialize_message(&msg).unwrap();
        
        // Try to deserialize with truncated data
        let result: Result<Message, _> = serializer.deserialize_message(&encoded[..encoded.len() / 2]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_batch_deserialization() {
        let serializer = MessageSerializer::new();
        let garbage_data = vec![0xFF; 100];
        
        let result: Result<MessageBatch, _> = serializer.deserialize_batch(&garbage_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_message_error_display() {
        let err1 = MessageError::SerializationError("test error".to_string());
        assert!(err1.to_string().contains("Serialization error"));
        
        let err2 = MessageError::DeserializationError("test error".to_string());
        assert!(err2.to_string().contains("Deserialization error"));
        
        let err3 = MessageError::InvalidMessage("test".to_string());
        assert!(err3.to_string().contains("Invalid message"));
    }

    // ============================================
    // Edge Case Tests
    // ============================================

    #[test]
    fn test_empty_payload() {
        let msg = Message::new([0u8; 8], 1, 1, vec![], MessageType::Data);
        assert_eq!(msg.header.length, 0);
        assert_eq!(msg.total_size(), MessageHeader::SIZE);
    }

    #[test]
    fn test_max_sequence_number() {
        let msg = Message::new([0u8; 8], u32::MAX, 1, b"test".to_vec(), MessageType::Data);
        assert_eq!(msg.header.sequence, u32::MAX);
    }

    #[test]
    fn test_max_topic_number() {
        let msg = Message::new([0u8; 8], 1, u32::MAX, b"test".to_vec(), MessageType::Data);
        assert_eq!(msg.header.topic, u32::MAX);
    }

    #[test]
    fn test_max_payload_length() {
        let max_payload = vec![0u8; u16::MAX as usize];
        let msg = Message::new([0u8; 8], 1, 1, max_payload.clone(), MessageType::Data);
        assert_eq!(msg.header.length, u16::MAX);
    }

    #[test]
    fn test_special_characters_in_payload() {
        let special_payload = vec![0x00, 0x01, 0xFF, 0xFE, 0x7F, 0x80];
        let msg = Message::new([0u8; 8], 1, 1, special_payload.clone(), MessageType::Data);
        
        let serializer = MessageSerializer::new();
        let encoded = serializer.serialize_message(&msg).unwrap();
        let decoded = serializer.deserialize_message(&encoded).unwrap();
        
        assert_eq!(decoded.payload, special_payload);
    }

    #[test]
    fn test_unicode_payload() {
        let unicode_string = "Hello, 世界! 🌍 Émojis: 🚀💻🔒";
        let payload = unicode_string.as_bytes().to_vec();
        let msg = Message::new([0u8; 8], 1, 1, payload.clone(), MessageType::Data);
        
        let serializer = MessageSerializer::new();
        let encoded = serializer.serialize_message(&msg).unwrap();
        let decoded = serializer.deserialize_message(&encoded).unwrap();
        
        assert_eq!(decoded.payload, payload);
        assert_eq!(String::from_utf8(decoded.payload).unwrap(), unicode_string);
    }

    #[test]
    fn test_zero_timestamp() {
        let mut batch = MessageBatch::new();
        batch.timestamp = 0;
        assert_eq!(batch.timestamp, 0);
    }

    #[test]
    fn test_negative_timestamp() {
        let mut batch = MessageBatch::new();
        batch.timestamp = -1;
        assert_eq!(batch.timestamp, -1);
    }

    #[test]
    fn test_all_sender_bytes() {
        for i in 0u8..=255 {
            let sender = [i; 8];
            let msg = Message::new(sender, 1, 1, b"test".to_vec(), MessageType::Data);
            assert_eq!(msg.header.sender, sender);
        }
    }

    #[test]
    fn test_batch_with_single_message() {
        let mut batch = MessageBatch::new();
        batch.push(Message::new([0u8; 8], 1, 1, b"single".to_vec(), MessageType::Data));
        
        assert_eq!(batch.len(), 1);
        assert!(!batch.is_empty());
    }

    #[test]
    fn test_message_clone() {
        let msg = Message::new([0u8; 8], 1, 1, b"test".to_vec(), MessageType::Data);
        let cloned = msg.clone();
        
        assert_eq!(msg.header.sequence, cloned.header.sequence);
        assert_eq!(msg.payload, cloned.payload);
    }

    #[test]
    fn test_batch_clone() {
        let mut batch = MessageBatch::new();
        batch.push(Message::new([0u8; 8], 1, 1, b"test".to_vec(), MessageType::Data));
        
        let cloned = batch.clone();
        assert_eq!(batch.len(), cloned.len());
        assert_eq!(batch.batch_id, cloned.batch_id);
    }

    #[test]
    fn test_flags_combination() {
        let mut flags = MessageFlags::NONE;
        flags.0 = MessageFlags::ENCRYPTED.0 | MessageFlags::BATCHED.0 | MessageFlags::PRIORITY.0;
        
        assert!(flags.is_encrypted());
        assert!(flags.is_batched());
        assert!(flags.0 & MessageFlags::PRIORITY.0 != 0);
    }

    #[test]
    fn test_consecutive_sequence_numbers() {
        let mut prev_seq: Option<u32> = None;
        for i in 0..100 {
            let msg = Message::new([0u8; 8], i, 1, b"test".to_vec(), MessageType::Data);
            if let Some(prev) = prev_seq {
                assert_eq!(msg.header.sequence, prev + 1);
            }
            prev_seq = Some(msg.header.sequence);
        }
    }

    #[test]
    fn test_round_trip_all_message_types() {
        let types = vec![
            (MessageType::Data, "data"),
            (MessageType::Request, "request"),
            (MessageType::Response, "response"),
            (MessageType::Discovery, "discovery"),
            (MessageType::Heartbeat, "heartbeat"),
            (MessageType::Ack, "ack"),
            (MessageType::Nak, "nak"),
        ];
        
        let serializer = MessageSerializer::new();
        
        for (msg_type, name) in types {
            let msg = Message::new([0u8; 8], 1, 1, name.as_bytes().to_vec(), msg_type);
            let encoded = serializer.serialize_message(&msg).unwrap();
            let decoded = serializer.deserialize_message(&encoded).unwrap();
            
            assert_eq!(decoded.payload, name.as_bytes());
        }
    }

    #[test]
    fn test_serialize_message_no_payload() {
        let msg = Message {
            header: MessageHeader::new([0u8; 8], 1, 1, 0),
            payload: vec![],
            msg_type: MessageType::Heartbeat,
            encrypted_payload: None,
        };
        
        let serializer = MessageSerializer::new();
        let encoded = serializer.serialize_message(&msg).unwrap();
        assert!(!encoded.is_empty());
        
        let decoded = serializer.deserialize_message(&encoded).unwrap();
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn test_message_with_encrypted_payload() {
        let msg = Message {
            header: MessageHeader::new([0u8; 8], 1, 1, 0).with_flags(MessageFlags::ENCRYPTED),
            payload: vec![],
            msg_type: MessageType::Data,
            encrypted_payload: Some(EncryptedPayload {
                session_id: "session-123".to_string(),
                ciphertext: vec![1, 2, 3],
                message_number: 1,
                is_prekey_message: false,
            }),
        };
        
        let serializer = MessageSerializer::new();
        let encoded = serializer.serialize_message(&msg).unwrap();
        let decoded = serializer.deserialize_message(&encoded).unwrap();
        
        assert!(decoded.header.flags.is_encrypted());
        assert!(decoded.encrypted_payload.is_some());
        
        let ep = decoded.encrypted_payload.unwrap();
        assert_eq!(ep.session_id, "session-123");
        assert_eq!(ep.ciphertext, vec![1, 2, 3]);
    }

    #[test]
    fn test_batch_id_consistency() {
        let mut batch = MessageBatch::new();
        let id_before = batch.batch_id;
        batch.push(Message::new([0u8; 8], 1, 1, b"test".to_vec(), MessageType::Data));
        let id_after = batch.batch_id;
        
        assert_eq!(id_before, id_after);
    }

    #[test]
    fn test_different_batch_ids() {
        let batch1 = MessageBatch::new();
        let batch2 = MessageBatch::new();
        
        // Different batches should have different IDs (with high probability)
        // Note: UUID collisions are extremely unlikely but theoretically possible
        assert_ne!(batch1.batch_id, batch2.batch_id);
    }

    #[test]
    fn test_payload_exact_size_boundary() {
        // Test payload at exactly boundary values
        for size in [0, 1, 255, 256, 1023, 1024, 1025, 65535].iter() {
            if *size <= u16::MAX as usize {
                let payload = vec![0u8; *size];
                let msg = Message::new([0u8; 8], 1, 1, payload, MessageType::Data);
                assert_eq!(msg.header.length as usize, *size);
            }
        }
    }

    #[test]
    fn test_multiple_encrypted_payloads() {
        let payloads: Vec<EncryptedPayload> = (0..5).map(|i| EncryptedPayload {
            session_id: format!("session-{}", i),
            ciphertext: vec![i as u8; 32],
            message_number: i as u32,
            is_prekey_message: i % 2 == 0,
        }).collect();
        
        for (i, ep) in payloads.iter().enumerate() {
            assert_eq!(ep.session_id, format!("session-{}", i));
            assert_eq!(ep.message_number, i as u32);
            assert_eq!(ep.is_prekey_message, i % 2 == 0);
        }
    }

    #[test]
    fn test_serialization_idempotency() {
        let msg = Message::new([0u8; 8], 1, 1, b"test".to_vec(), MessageType::Data);
        let serializer = MessageSerializer::new();
        
        let encoded1 = serializer.serialize_message(&msg).unwrap();
        let decoded = serializer.deserialize_message(&encoded1).unwrap();
        let encoded2 = serializer.serialize_message(&decoded).unwrap();
        
        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn test_header_size_constant() {
        assert_eq!(MessageHeader::SIZE, 19);
        
        // Verify: flags(1) + sender(8) + seq(4) + topic(4) + len(2) = 19
        assert_eq!(1 + 8 + 4 + 4 + 2, 19);
    }

    #[test]
    fn test_batch_timestamp_range() {
        let batch = MessageBatch::new();
        // Should be a valid Unix timestamp
        assert!(batch.timestamp > 0);
        // Should be reasonably current (within last year)
        let now = chrono::Utc::now().timestamp();
        assert!(batch.timestamp > now - 31536000); // 1 year in seconds
        assert!(batch.timestamp <= now + 1);
    }

    #[test]
    fn test_message_type_debug() {
        let msg_types = vec![
            MessageType::Data,
            MessageType::Request,
            MessageType::Response,
        ];
        
        for msg_type in msg_types {
            let debug_str = format!("{:?}", msg_type);
            assert!(!debug_str.is_empty());
        }
    }

    #[test]
    fn test_flags_debug() {
        let flags = MessageFlags::ENCRYPTED | MessageFlags::BATCHED;
        let debug_str = format!("{:?}", flags);
        assert!(!debug_str.is_empty());
    }

    #[test]
    fn test_message_debug() {
        let msg = Message::new([0u8; 8], 1, 1, b"test".to_vec(), MessageType::Data);
        let debug_str = format!("{:?}", msg);
        assert!(debug_str.contains("Message"));
    }

    #[test]
    fn test_batch_debug() {
        let mut batch = MessageBatch::new();
        batch.push(Message::new([0u8; 8], 1, 1, b"test".to_vec(), MessageType::Data));
        let debug_str = format!("{:?}", batch);
        assert!(debug_str.contains("MessageBatch"));
    }
}
