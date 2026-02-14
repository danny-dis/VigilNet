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

    #[test]
    fn test_message_serialization() {
        let serializer = MessageSerializer::new();
        let msg = Message::new(
            [0u8; 8],
            1,
            100,
            b"Hello, World!".to_vec(),
            MessageType::Data,
        );

        let encoded = serializer.serialize_message(&msg).unwrap();
        let decoded = serializer.deserialize_message(&encoded).unwrap();

        assert_eq!(msg.header.sequence, decoded.header.sequence);
        assert_eq!(msg.payload, decoded.payload);
    }

    #[test]
    fn test_message_batch() {
        let mut batch = MessageBatch::new();
        batch.push(Message::new([0u8; 8], 1, 100, b"msg1".to_vec(), MessageType::Data));
        batch.push(Message::new([0u8; 8], 2, 100, b"msg2".to_vec(), MessageType::Data));

        assert_eq!(batch.len(), 2);
        assert!(!batch.is_empty());
    }
}
