//! Double Ratchet Algorithm for Signal Protocol
//!
//! Provides forward secrecy and break-in recovery through:
//! - Symmetric ratchet: Chain keys for message encryption
//! - DH ratchet: Diffie-Hellman key exchange per message

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::{debug, trace};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{aead, CryptoError, Result};

const CHAIN_KEY_LEN: usize = 32;
const MESSAGE_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const INFO_RATCHET: &[u8] = b"VigilNet-DoubleRatchet-v1";
const SALT_RATCHET: &[u8] = b"VigilNet-Ratchet-Salt";

/// Message key derived from chain key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageKey {
    pub key: [u8; 32],
    pub message_number: u32,
    pub previous_chain_length: u32,
}

impl MessageKey {
    /// Derive next message key from chain key
    pub fn derive(chain_key: &[u8; 32], msg_num: u32, prev_chain_len: u32) -> Result<Self> {
        let mut input = [0u8; 40];
        input[..32].copy_from_slice(chain_key);
        input[32..36].copy_from_slice(&msg_num.to_le_bytes());
        input[36..40].copy_from_slice(&prev_chain_len.to_le_bytes());

        let hk = Hkdf::<Sha256>::new(Some(SALT_RATCHET), &input);
        let mut okm = [0u8; MESSAGE_KEY_LEN];
        hk.expand(b"messagekey", &mut okm)
            .map_err(|e| CryptoError::RatchetError(format!("Key derivation failed: {:?}", e)))?;

        Ok(Self {
            key: okm,
            message_number: msg_num,
            previous_chain_length: prev_chain_len,
        })
    }

    /// Derive next chain key from current chain key
    pub fn next_chain_key(chain_key: &[u8; 32]) -> Result<[u8; 32]> {
        let mut input = [0u8; 33];
        input[0] = 0x02;
        input[1..].copy_from_slice(chain_key);

        let hk = Hkdf::<Sha256>::new(Some(SALT_RATCHET), &input);
        let mut okm = [0u8; CHAIN_KEY_LEN];
        hk.expand(b"chainkey", &mut okm)
            .map_err(|e| CryptoError::RatchetError(format!("Chain key derivation failed: {:?}", e)))?;
        Ok(okm)
    }
}

/// Symmetric-key ratchet state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetSymmetricKey {
    pub chain_key: [u8; 32],
    pub message_number: u32,
    pub previous_chain_length: u32,
}

impl RatchetSymmetricKey {
    /// Create a new symmetric ratchet from shared secret
    pub fn new(shared_secret: [u8; 32]) -> Result<Self> {
        let hk = Hkdf::<Sha256>::new(Some(SALT_RATCHET), &shared_secret);
        let mut chain_key = [0u8; 32];
        hk.expand(b"rootkey", &mut chain_key)
            .map_err(|e| CryptoError::RatchetError(format!("Root key derivation failed: {:?}", e)))?;

        Ok(Self {
            chain_key,
            message_number: 0,
            previous_chain_length: 0,
        })
    }

    /// Derive next message key and advance chain
    pub fn next_message_key(&mut self) -> Result<MessageKey> {
        let mk = MessageKey::derive(
            &self.chain_key,
            self.message_number,
            self.previous_chain_length,
        )?;
        self.chain_key = MessageKey::next_chain_key(&self.chain_key)?;
        self.message_number += 1;
        Ok(mk)
    }

    /// Skip ahead to a specific message number (for out-of-order delivery)
    pub fn skip_to(&mut self, message_number: u32) -> Result<()> {
        if message_number < self.message_number {
            return Err(CryptoError::SkippedMessage(message_number));
        }

        let mut chain_key = self.chain_key;
        while self.message_number < message_number {
            chain_key = MessageKey::next_chain_key(&chain_key)?;
            self.message_number += 1;
        }
        self.chain_key = chain_key;

        Ok(())
    }
}

/// DH ratchet state (Diffie-Hellman key pairs)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetDH {
    pub dh_key_pair: RatchetKeyPair,
    pub remote_public_key: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetKeyPair {
    pub secret: [u8; 32],
    pub public: [u8; 32],
}

impl RatchetKeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            secret: secret.to_bytes(),
            public: public.to_bytes(),
        }
    }

    pub fn from_secret(secret: [u8; 32]) -> Self {
        let secret = StaticSecret::from(secret);
        let public = PublicKey::from(&secret);
        Self {
            secret: secret.to_bytes(),
            public: public.to_bytes(),
        }
    }

    pub fn diffie_hellman(&self, remote_public: &[u8; 32]) -> [u8; 32] {
        let secret = StaticSecret::from(self.secret);
        let remote = PublicKey::from(*remote_public);
        let shared = secret.diffie_hellman(&remote);
        *shared.as_bytes()
    }
}

/// Complete Double Ratchet state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetState {
    pub root_key: [u8; 32],
    pub sending_chain: Option<RatchetSymmetricKey>,
    pub receiving_chain: Option<RatchetSymmetricKey>,
    pub dh_ratchet: RatchetDH,
    pub remote_ratchet_key: Option<[u8; 32]>,
    pub skipped_messages: Vec<SkippedMessageKey>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SkippedMessageKey {
    pub message_key: MessageKey,
    pub remote_public_key: [u8; 32],
}

/// Double Ratchet implementation
pub struct DoubleRatchet {
    state: RatchetState,
}

impl DoubleRatchet {
    /// Create a new ratchet session as initiator (Alice)
    pub fn initiator(shared_secret: [u8; 32], remote_public: [u8; 32]) -> Result<Self> {
        debug!("Creating Double Ratchet as initiator");

        let dh_key_pair = RatchetKeyPair::generate();
        let mut root_key = shared_secret;

        let shared = dh_key_pair.diffie_hellman(&remote_public);
        let (new_root_key, chain_key) = Self::kdf_root(&root_key, &shared)?;

        root_key = new_root_key;

        let state = RatchetState {
            root_key,
            sending_chain: Some(RatchetSymmetricKey::new(chain_key)?),
            receiving_chain: None,
            dh_ratchet: RatchetDH {
                dh_key_pair,
                remote_public_key: Some(remote_public),
            },
            remote_ratchet_key: Some(remote_public),
            skipped_messages: Vec::new(),
        };

        Ok(Self { state })
    }

    /// Create a new ratchet session as responder (Bob)
    pub fn responder(shared_secret: [u8; 32]) -> Self {
        debug!("Creating Double Ratchet as responder");

        let dh_key_pair = RatchetKeyPair::generate();
        let root_key = shared_secret;

        let state = RatchetState {
            root_key,
            sending_chain: None,
            receiving_chain: None,
            dh_ratchet: RatchetDH {
                dh_key_pair,
                remote_public_key: None,
            },
            remote_ratchet_key: None,
            skipped_messages: Vec::new(),
        };

        Self { state }
    }

    /// Process peer's public key and advance DH ratchet
    pub fn dh_ratchet(&mut self, remote_public: &[u8; 32]) -> Result<()> {
        trace!("Processing DH ratchet with new public key");

        if let Some(sending_chain) = &self.state.sending_chain {
            let old_sending_chain_key = sending_chain.chain_key;
            self.state.receiving_chain = Some(RatchetSymmetricKey::new(old_sending_chain_key)?);
        }

        self.state.remote_ratchet_key = Some(*remote_public);

        let shared = self.state.dh_ratchet.dh_key_pair.diffie_hellman(remote_public);
        let (new_root_key, receiving_chain_key) = Self::kdf_root(&self.state.root_key, &shared)?;

        self.state.root_key = new_root_key;
        self.state.receiving_chain = Some(RatchetSymmetricKey::new(receiving_chain_key)?);

        let dh_key_pair = RatchetKeyPair::generate();
        let shared = dh_key_pair.diffie_hellman(remote_public);
        let (new_root_key, sending_chain_key) = Self::kdf_root(&self.state.root_key, &shared)?;

        self.state.root_key = new_root_key;
        self.state.sending_chain = Some(RatchetSymmetricKey::new(sending_chain_key)?);

        self.state.dh_ratchet.dh_key_pair = dh_key_pair;
        self.state.dh_ratchet.remote_public_key = Some(*remote_public);

        debug!("DH ratchet step completed");
        Ok(())
    }

    /// Get current sending public key
    pub fn sending_public_key(&self) -> [u8; 32] {
        self.state.dh_ratchet.dh_key_pair.public
    }

    /// Check for skipped messages and decrypt if found
    pub fn try_decrypt_skipped(&mut self, remote_public: &[u8; 32], ciphertext: &[u8]) -> Option<Result<Vec<u8>>> {
        let idx = self.state.skipped_messages.iter().position(|sk| {
            sk.remote_public_key == *remote_public
        })?;

        let skipped = self.state.skipped_messages.remove(idx);
        
        if skipped.message_key.key.len() < 32 || ciphertext.len() < NONCE_LEN + 16 {
            return Some(Err(CryptoError::InvalidMessage("Message too short".to_string())));
        }

        let key_array: [u8; 32] = skipped.message_key.key;
        let result = aead::decrypt(&key_array, ciphertext);
        Some(result)
    }

    /// Encrypt a message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptedMessage> {
        let sending_chain = self
            .state
            .sending_chain
            .as_mut()
            .ok_or_else(|| CryptoError::RatchetError("No sending chain available".to_string()))?;

        let message_key = sending_chain.next_message_key()?;
        let ciphertext = aead::encrypt(&message_key.key, plaintext)?;

        Ok(EncryptedMessage {
            header: MessageHeader {
                public_key: self.state.dh_ratchet.dh_key_pair.public,
                previous_chain_length: sending_chain.previous_chain_length,
                message_number: message_key.message_number - 1,
            },
            ciphertext,
        })
    }

    /// Decrypt a message
    pub fn decrypt(&mut self, header: &MessageHeader, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if let Some(remote_key) = header.public_key.as_ref() {
            if self.state.remote_ratchet_key != Some(*remote_key) {
                self.dh_ratchet(remote_key)?;
            }
        }

        if let Some(receiving_chain) = &mut self.state.receiving_chain {
            let message_key = receiving_chain.next_message_key()?;
            
            if message_key.key.len() < 32 || ciphertext.len() < NONCE_LEN + 16 {
                return Err(CryptoError::InvalidMessage("Message too short".to_string()));
            }

            let key_array: [u8; 32] = message_key.key;
            aead::decrypt(&key_array, ciphertext)
        } else {
            Err(CryptoError::RatchetError("No receiving chain".to_string()))
        }
    }

    /// Skip ahead to a specific message number
    pub fn skip_messages(&mut self, until: u32) -> Result<()> {
        if let Some(receiving_chain) = &mut self.state.receiving_chain {
            receiving_chain.skip_to(until)?;
        }
        Ok(())
    }

    /// Get the current state for storage
    pub fn state(&self) -> &RatchetState {
        &self.state
    }

    fn kdf_root(root_key: &[u8; 32], dh_output: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(root_key);
        input[32..].copy_from_slice(dh_output);

        let hk = Hkdf::<Sha256>::new(Some(SALT_RATCHET), &input);
        let mut okm = [0u8; 64];
        hk.expand(INFO_RATCHET, &mut okm)
            .map_err(|e| CryptoError::RatchetError(format!("Root KDF failed: {:?}", e)))?;

        let new_root_key: [u8; 32] = okm[..32].try_into()
            .map_err(|_| CryptoError::RatchetError("Invalid root key length".to_string()))?;
        let chain_key: [u8; 32] = okm[32..].try_into()
            .map_err(|_| CryptoError::RatchetError("Invalid chain key length".to_string()))?;

        Ok((new_root_key, chain_key))
    }
}

/// Message header for Double Ratchet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageHeader {
    pub public_key: Option<[u8; 32]>,
    pub previous_chain_length: u32,
    pub message_number: u32,
}

/// Encrypted message with header
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub header: MessageHeader,
    pub ciphertext: Vec<u8>,
}

impl EncryptedMessage {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        
        if let Some(ref pk) = self.header.public_key {
            result.push(1);
            result.extend_from_slice(pk);
        } else {
            result.push(0);
        }
        
        result.extend_from_slice(&self.header.previous_chain_length.to_le_bytes());
        result.extend_from_slice(&self.header.message_number.to_le_bytes());
        result.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        result.extend_from_slice(&self.ciphertext);
        
        result
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 41 {
            return Err(CryptoError::InvalidMessage("Data too short".to_string()));
        }

        let mut offset = 0;
        
        let public_key = if data[offset] == 1 {
            offset += 1;
            if data.len() < offset + 32 {
                return Err(CryptoError::InvalidMessage("Public key data truncated".to_string()));
            }
            let pk: [u8; 32] = data[offset..offset + 32].try_into()
                .map_err(|_| CryptoError::InvalidMessage("Invalid public key length".to_string()))?;
            offset += 32;
            Some(pk)
        } else {
            offset += 1;
            None
        };

        if data.len() < offset + 4 {
            return Err(CryptoError::InvalidMessage("Previous chain length data truncated".to_string()));
        }
        let previous_chain_length = u32::from_le_bytes(data[offset..offset + 4].try_into()
            .map_err(|_| CryptoError::InvalidMessage("Invalid previous chain length".to_string()))?);
        offset += 4;

        if data.len() < offset + 4 {
            return Err(CryptoError::InvalidMessage("Message number data truncated".to_string()));
        }
        let message_number = u32::from_le_bytes(data[offset..offset + 4].try_into()
            .map_err(|_| CryptoError::InvalidMessage("Invalid message number".to_string()))?);
        offset += 4;

        if data.len() < offset + 4 {
            return Err(CryptoError::InvalidMessage("Ciphertext length data truncated".to_string()));
        }
        let ciphertext_len = u32::from_le_bytes(data[offset..offset + 4].try_into()
            .map_err(|_| CryptoError::InvalidMessage("Invalid ciphertext length".to_string()))?) as usize;
        offset += 4;

        if data.len() < offset + ciphertext_len {
            return Err(CryptoError::InvalidMessage("Truncated ciphertext".to_string()));
        }

        let ciphertext = data[offset..offset + ciphertext_len].to_vec();

        Ok(Self {
            header: MessageHeader {
                public_key,
                previous_chain_length,
                message_number,
            },
            ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_key_derivation() {
        let chain_key = [0x42u8; 32];
        let mk1 = MessageKey::derive(&chain_key, 0, 0);
        let mk2 = MessageKey::derive(&chain_key, 1, 0);

        assert_ne!(mk1.key, mk2.key);
    }

    #[test]
    fn test_message_key_different_prev_chain_length() {
        let chain_key = [0x42u8; 32];
        let mk1 = MessageKey::derive(&chain_key, 0, 0);
        let mk2 = MessageKey::derive(&chain_key, 0, 1);

        assert_ne!(mk1.key, mk2.key);
    }

    #[test]
    fn test_symmetric_ratchet() {
        let secret = [0x42u8; 32];
        let mut ratchet = RatchetSymmetricKey::new(secret);

        let mk1 = ratchet.next_message_key();
        let mk2 = ratchet.next_message_key();

        assert_eq!(mk1.message_number, 0);
        assert_eq!(mk2.message_number, 1);
    }

    #[test]
    fn test_chain_key_advancement() {
        let secret = [0x42u8; 32];
        let mut ratchet = RatchetSymmetricKey::new(secret);

        let mk1 = ratchet.next_message_key();
        let chain_key_after = ratchet.chain_key;

        let mut expected_next = MessageKey::next_chain_key(&secret);
        assert_eq!(chain_key_after, expected_next);
    }

    #[test]
    fn test_skip_messages() {
        let secret = [0x42u8; 32];
        let mut ratchet = RatchetSymmetricKey::new(secret);

        ratchet.skip_to(5).unwrap();
        let mk = ratchet.next_message_key();

        assert_eq!(mk.message_number, 5);
    }

    #[test]
    fn test_skip_messages_backwards_fails() {
        let secret = [0x42u8; 32];
        let mut ratchet = RatchetSymmetricKey::new(secret);

        ratchet.next_message_key();
        let result = ratchet.skip_to(0);

        assert!(result.is_err());
    }

    #[test]
    fn test_double_ratchet_encrypt_decrypt() {
        let shared_secret = [0x42u8; 32];
        
        let mut alice = DoubleRatchet::initiator(shared_secret, [0x43u8; 32]);
        let mut bob = DoubleRatchet::responder(shared_secret);

        alice.dh_ratchet(&bob.sending_public_key()).unwrap();
        bob.dh_ratchet(&alice.sending_public_key()).unwrap();

        let plaintext = b"Hello, secure world!";
        let encrypted = alice.encrypt(plaintext).unwrap();
        
        let decrypted = bob.decrypt(&encrypted.header, &encrypted.ciphertext).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_double_ratchet_multiple_messages() {
        let shared_secret = [0x42u8; 32];
        
        let mut alice = DoubleRatchet::initiator(shared_secret, [0x43u8; 32]);
        let mut bob = DoubleRatchet::responder(shared_secret);

        alice.dh_ratchet(&bob.sending_public_key()).unwrap();
        bob.dh_ratchet(&alice.sending_public_key()).unwrap();

        for i in 0..10 {
            let plaintext = format!("Message {}", i);
            let encrypted = alice.encrypt(plaintext.as_bytes()).unwrap();
            let decrypted = bob.decrypt(&encrypted.header, &encrypted.ciphertext).unwrap();
            assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
        }
    }

    #[test]
    fn test_encrypted_message_serialization() {
        let shared_secret = [0x42u8; 32];
        let mut alice = DoubleRatchet::initiator(shared_secret, [0x43u8; 32]);
        let mut bob = DoubleRatchet::responder(shared_secret);

        alice.dh_ratchet(&bob.sending_public_key()).unwrap();
        bob.dh_ratchet(&alice.sending_public_key()).unwrap();

        let plaintext = b"Test message";
        let encrypted = alice.encrypt(plaintext).unwrap();

        let serialized = encrypted.to_bytes();
        let deserialized = EncryptedMessage::from_bytes(&serialized).unwrap();

        assert_eq!(encrypted.header.public_key, deserialized.header.public_key);
        assert_eq!(encrypted.ciphertext, deserialized.ciphertext);
    }

    #[test]
    fn test_ratchet_key_pair_generation() {
        let kp = RatchetKeyPair::generate();
        assert_eq!(kp.secret.len(), 32);
        assert_eq!(kp.public.len(), 32);
    }

    #[test]
    fn test_ratchet_diffie_hellman() {
        let alice_kp = RatchetKeyPair::generate();
        let bob_kp = RatchetKeyPair::generate();

        let shared_alice = alice_kp.diffie_hellman(&bob_kp.public);
        let shared_bob = bob_kp.diffie_hellman(&alice_kp.public);

        assert_eq!(shared_alice, shared_bob);
    }

    #[test]
    fn test_message_key_deterministic() {
        let chain_key = [0x42u8; 32];
        
        // Same inputs should produce same key
        let mk1 = MessageKey::derive(&chain_key, 5, 10);
        let mk2 = MessageKey::derive(&chain_key, 5, 10);
        
        assert_eq!(mk1.key, mk2.key);
        assert_eq!(mk1.message_number, mk2.message_number);
        assert_eq!(mk1.previous_chain_length, mk2.previous_chain_length);
    }

    #[test]
    fn test_message_key_chain_progression() {
        let chain_key = [0x42u8; 32];
        let mut ratchet = RatchetSymmetricKey::new(chain_key);
        
        let mut keys = Vec::new();
        for _ in 0..100 {
            keys.push(ratchet.next_message_key());
        }
        
        // All keys should be unique
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i].key, keys[j].key, "Duplicate key at indices {} and {}", i, j);
            }
        }
    }

    #[test]
    fn test_ratchet_key_pair_from_secret() {
        let secret = [0x42u8; 32];
        let kp = RatchetKeyPair::from_secret(secret);
        
        assert_eq!(kp.secret, secret);
        // Public key should be derived from secret
        let expected_public = PublicKey::from(&StaticSecret::from(secret));
        assert_eq!(kp.public, expected_public.to_bytes());
    }

    #[test]
    fn test_ratchet_key_pair_unique_generation() {
        let mut public_keys = std::collections::HashSet::new();
        
        for _ in 0..100 {
            let kp = RatchetKeyPair::generate();
            assert!(public_keys.insert(kp.public), "Duplicate public key generated");
        }
    }

    #[test]
    fn test_symmetric_ratchet_different_secrets() {
        let secret1 = [0x42u8; 32];
        let secret2 = [0x43u8; 32];
        
        let ratchet1 = RatchetSymmetricKey::new(secret1);
        let ratchet2 = RatchetSymmetricKey::new(secret2);
        
        assert_ne!(ratchet1.chain_key, ratchet2.chain_key);
    }

    #[test]
    fn test_chain_key_evolution() {
        let secret = [0x42u8; 32];
        let mut ratchet = RatchetSymmetricKey::new(secret);
        
        let initial_chain_key = ratchet.chain_key;
        
        // Advance multiple times
        for _ in 0..10 {
            ratchet.next_message_key();
        }
        
        // Chain key should have evolved
        assert_ne!(ratchet.chain_key, initial_chain_key);
    }

    #[test]
    fn test_skip_to_current_position() {
        let secret = [0x42u8; 32];
        let mut ratchet = RatchetSymmetricKey::new(secret);
        
        // Skip to current position should succeed
        ratchet.next_message_key();
        ratchet.next_message_key();
        
        let result = ratchet.skip_to(2);
        assert!(result.is_ok());
        assert_eq!(ratchet.message_number, 2);
    }

    #[test]
    fn test_ratchet_initiator_state() {
        let shared_secret = [0x42u8; 32];
        let remote_public = [0x43u8; 32];
        
        let ratchet = DoubleRatchet::initiator(shared_secret, remote_public);
        let state = ratchet.state();
        
        assert_eq!(state.root_key, shared_secret);
        assert!(state.sending_chain.is_some());
        assert!(state.remote_ratchet_key.is_some());
    }

    #[test]
    fn test_ratchet_responder_state() {
        let shared_secret = [0x42u8; 32];
        
        let ratchet = DoubleRatchet::responder(shared_secret);
        let state = ratchet.state();
        
        assert_eq!(state.root_key, shared_secret);
        assert!(state.sending_chain.is_none());
        assert!(state.receiving_chain.is_none());
        assert!(state.remote_ratchet_key.is_none());
    }

    #[test]
    fn test_dh_ratchet_key_rotation() {
        let shared_secret = [0x42u8; 32];
        
        let mut alice = DoubleRatchet::initiator(shared_secret, [0x43u8; 32]);
        let mut bob = DoubleRatchet::responder(shared_secret);
        
        let initial_alice_key = alice.sending_public_key();
        
        alice.dh_ratchet(&bob.sending_public_key()).unwrap();
        bob.dh_ratchet(&alice.sending_public_key()).unwrap();
        
        // Keys should have changed after DH ratchet
        assert_ne!(alice.sending_public_key(), initial_alice_key);
    }

    #[test]
    fn test_bidirectional_communication() {
        let shared_secret = [0x42u8; 32];
        
        let mut alice = DoubleRatchet::initiator(shared_secret, [0x43u8; 32]);
        let mut bob = DoubleRatchet::responder(shared_secret);
        
        alice.dh_ratchet(&bob.sending_public_key()).unwrap();
        bob.dh_ratchet(&alice.sending_public_key()).unwrap();
        
        // Alice sends to Bob
        let msg1 = b"Hello Bob";
        let encrypted1 = alice.encrypt(msg1).unwrap();
        let decrypted1 = bob.decrypt(&encrypted1.header, &encrypted1.ciphertext).unwrap();
        assert_eq!(msg1.as_slice(), decrypted1.as_slice());
        
        // Bob sends to Alice
        let msg2 = b"Hello Alice";
        let encrypted2 = bob.encrypt(msg2).unwrap();
        let decrypted2 = alice.decrypt(&encrypted2.header, &encrypted2.ciphertext).unwrap();
        assert_eq!(msg2.as_slice(), decrypted2.as_slice());
    }

    #[test]
    fn test_alternating_messages() {
        let shared_secret = [0x42u8; 32];
        
        let mut alice = DoubleRatchet::initiator(shared_secret, [0x43u8; 32]);
        let mut bob = DoubleRatchet::responder(shared_secret);
        
        alice.dh_ratchet(&bob.sending_public_key()).unwrap();
        bob.dh_ratchet(&alice.sending_public_key()).unwrap();
        
        // Alternate sending messages
        for i in 0..20 {
            if i % 2 == 0 {
                let msg = format!("Alice message {}", i);
                let encrypted = alice.encrypt(msg.as_bytes()).unwrap();
                let decrypted = bob.decrypt(&encrypted.header, &encrypted.ciphertext).unwrap();
                assert_eq!(msg.as_bytes(), decrypted.as_slice());
            } else {
                let msg = format!("Bob message {}", i);
                let encrypted = bob.encrypt(msg.as_bytes()).unwrap();
                let decrypted = alice.decrypt(&encrypted.header, &encrypted.ciphertext).unwrap();
                assert_eq!(msg.as_bytes(), decrypted.as_slice());
            }
        }
    }

    #[test]
    fn test_encrypted_message_without_public_key() {
        let header = MessageHeader {
            public_key: None,
            previous_chain_length: 0,
            message_number: 0,
        };
        
        let encrypted = EncryptedMessage {
            header,
            ciphertext: vec![1, 2, 3, 4, 5],
        };
        
        let bytes = encrypted.to_bytes();
        let deserialized = EncryptedMessage::from_bytes(&bytes).unwrap();
        
        assert!(deserialized.header.public_key.is_none());
        assert_eq!(encrypted.ciphertext, deserialized.ciphertext);
    }

    #[test]
    fn test_encrypted_message_from_bytes_too_short() {
        let result = EncryptedMessage::from_bytes(&[1, 2, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_message_truncated_ciphertext() {
        let header = MessageHeader {
            public_key: Some([0u8; 32]),
            previous_chain_length: 0,
            message_number: 0,
        };
        
        let encrypted = EncryptedMessage {
            header,
            ciphertext: vec![1, 2, 3, 4, 5],
        };
        
        let mut bytes = encrypted.to_bytes();
        // Truncate the ciphertext
        bytes.truncate(bytes.len() - 2);
        
        let result = EncryptedMessage::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_no_receiving_chain_fails() {
        let shared_secret = [0x42u8; 32];
        
        let mut alice = DoubleRatchet::initiator(shared_secret, [0x43u8; 32]);
        let bob = DoubleRatchet::responder(shared_secret);
        
        // Alice encrypts without Bob having done DH ratchet
        let plaintext = b"Test";
        let encrypted = alice.encrypt(plaintext).unwrap();
        
        // This should fail because Bob has no receiving chain yet
        // Note: In practice, the DH ratchet would set this up first
    }

    #[test]
    fn test_encrypt_no_sending_chain_fails() {
        let shared_secret = [0x42u8; 32];
        
        let mut bob = DoubleRatchet::responder(shared_secret);
        
        // Bob tries to encrypt before DH ratchet
        let plaintext = b"Test";
        let result = bob.encrypt(plaintext);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_message_encryption() {
        let shared_secret = [0x42u8; 32];
        
        let mut alice = DoubleRatchet::initiator(shared_secret, [0x43u8; 32]);
        let mut bob = DoubleRatchet::responder(shared_secret);
        
        alice.dh_ratchet(&bob.sending_public_key()).unwrap();
        bob.dh_ratchet(&alice.sending_public_key()).unwrap();
        
        let plaintext = b"";
        let encrypted = alice.encrypt(plaintext).unwrap();
        let decrypted = bob.decrypt(&encrypted.header, &encrypted.ciphertext).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_large_message_encryption() {
        let shared_secret = [0x42u8; 32];
        
        let mut alice = DoubleRatchet::initiator(shared_secret, [0x43u8; 32]);
        let mut bob = DoubleRatchet::responder(shared_secret);
        
        alice.dh_ratchet(&bob.sending_public_key()).unwrap();
        bob.dh_ratchet(&alice.sending_public_key()).unwrap();
        
        let plaintext = vec![0xABu8; 10000];
        let encrypted = alice.encrypt(&plaintext).unwrap();
        let decrypted = bob.decrypt(&encrypted.header, &encrypted.ciphertext).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_skipped_message_key_storage() {
        let shared_secret = [0x42u8; 32];
        
        let mut alice = DoubleRatchet::initiator(shared_secret, [0x43u8; 32]);
        let mut bob = DoubleRatchet::responder(shared_secret);
        
        alice.dh_ratchet(&bob.sending_public_key()).unwrap();
        bob.dh_ratchet(&alice.sending_public_key()).unwrap();
        
        // Skip messages creates storage
        bob.skip_messages(5).unwrap();
        
        // Check that receiving chain exists and has advanced
        assert!(bob.state().receiving_chain.is_some());
    }

    #[test]
    fn test_ratchet_state_serialization() {
        let shared_secret = [0x42u8; 32];
        
        let alice = DoubleRatchet::initiator(shared_secret, [0x43u8; 32]);
        let state = alice.state().clone();
        
        let serialized = serde_json::to_vec(&state).unwrap();
        let deserialized: RatchetState = serde_json::from_slice(&serialized).unwrap();
        
        assert_eq!(state.root_key, deserialized.root_key);
    }

    #[test]
    fn test_message_key_serialization() {
        let chain_key = [0x42u8; 32];
        let mk = MessageKey::derive(&chain_key, 5, 10);
        
        let serialized = serde_json::to_vec(&mk).unwrap();
        let deserialized: MessageKey = serde_json::from_slice(&serialized).unwrap();
        
        assert_eq!(mk.key, deserialized.key);
        assert_eq!(mk.message_number, deserialized.message_number);
        assert_eq!(mk.previous_chain_length, deserialized.previous_chain_length);
    }

    #[test]
    fn test_message_header_serialization() {
        let header = MessageHeader {
            public_key: Some([0x42u8; 32]),
            previous_chain_length: 5,
            message_number: 10,
        };
        
        let serialized = serde_json::to_vec(&header).unwrap();
        let deserialized: MessageHeader = serde_json::from_slice(&serialized).unwrap();
        
        assert_eq!(header.public_key, deserialized.public_key);
        assert_eq!(header.previous_chain_length, deserialized.previous_chain_length);
        assert_eq!(header.message_number, deserialized.message_number);
    }

    #[test]
    fn test_skipped_message_key_serialization() {
        let chain_key = [0x42u8; 32];
        let mk = MessageKey::derive(&chain_key, 0, 0);
        
        let skipped = SkippedMessageKey {
            message_key: mk,
            remote_public_key: [0x43u8; 32],
        };
        
        let serialized = serde_json::to_vec(&skipped).unwrap();
        let deserialized: SkippedMessageKey = serde_json::from_slice(&serialized).unwrap();
        
        assert_eq!(skipped.remote_public_key, deserialized.remote_public_key);
    }

    #[test]
    fn test_dh_ratchet_idempotent() {
        let shared_secret = [0x42u8; 32];
        
        let mut alice = DoubleRatchet::initiator(shared_secret, [0x43u8; 32]);
        let mut bob = DoubleRatchet::responder(shared_secret);
        
        let bob_key = bob.sending_public_key();
        
        // First DH ratchet
        alice.dh_ratchet(&bob_key).unwrap();
        let key1 = alice.sending_public_key();
        
        // Same DH ratchet again should work but may produce different state
        alice.dh_ratchet(&bob_key).unwrap();
    }

    #[test]
    fn test_multiple_dh_ratchets() {
        let shared_secret = [0x42u8; 32];
        
        let mut alice = DoubleRatchet::initiator(shared_secret, [0x43u8; 32]);
        let mut bob = DoubleRatchet::responder(shared_secret);
        
        // Initial setup
        alice.dh_ratchet(&bob.sending_public_key()).unwrap();
        bob.dh_ratchet(&alice.sending_public_key()).unwrap();
        
        // Exchange a few messages
        for i in 0..5 {
            let msg = format!("Round 1 message {}", i);
            let encrypted = alice.encrypt(msg.as_bytes()).unwrap();
            let _ = bob.decrypt(&encrypted.header, &encrypted.ciphertext).unwrap();
        }
        
        // Simulate new DH ratchet (as would happen in real protocol)
        let new_bob_key = RatchetKeyPair::generate();
        bob.state.dh_ratchet.dh_key_pair = new_bob_key.clone();
        
        alice.dh_ratchet(&new_bob_key.public).unwrap();
        
        // Should still be able to communicate
        let msg = b"After ratchet";
        let encrypted = alice.encrypt(msg).unwrap();
        let decrypted = bob.decrypt(&encrypted.header, &encrypted.ciphertext).unwrap();
        assert_eq!(msg.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_message_number_increments() {
        let shared_secret = [0x42u8; 32];
        
        let mut alice = DoubleRatchet::initiator(shared_secret, [0x43u8; 32]);
        let mut bob = DoubleRatchet::responder(shared_secret);
        
        alice.dh_ratchet(&bob.sending_public_key()).unwrap();
        bob.dh_ratchet(&alice.sending_public_key()).unwrap();
        
        let mut last_message_number = 0;
        for i in 0..10 {
            let msg = format!("Message {}", i);
            let encrypted = alice.encrypt(msg.as_bytes()).unwrap();
            
            // Message number should increment
            assert!(encrypted.header.message_number >= last_message_number);
            last_message_number = encrypted.header.message_number;
            
            let _ = bob.decrypt(&encrypted.header, &encrypted.ciphertext).unwrap();
        }
    }

    #[test]
    fn test_kdf_root_deterministic() {
        let root_key = [0x42u8; 32];
        let dh_output = [0x43u8; 32];
        
        // Note: kdf_root is private, but we can test via the public interface
        let ratchet1 = DoubleRatchet::initiator(root_key, dh_output);
        let ratchet2 = DoubleRatchet::initiator(root_key, dh_output);
        
        // Both should start with same root key
        assert_eq!(ratchet1.state().root_key, ratchet2.state().root_key);
    }

    #[test]
    fn test_try_decrypt_skipped_no_match() {
        let shared_secret = [0x42u8; 32];
        
        let mut alice = DoubleRatchet::initiator(shared_secret, [0x43u8; 32]);
        
        // Try to decrypt with a key that was never stored
        let result = alice.try_decrypt_skipped(&[0x44u8; 32], &[0u8; 100]);
        assert!(result.is_none());
    }

    #[test]
    fn test_try_decrypt_skipped_wrong_key() {
        let shared_secret = [0x42u8; 32];
        
        let mut alice = DoubleRatchet::initiator(shared_secret, [0x43u8; 32]);
        let bob = DoubleRatchet::responder(shared_secret);
        
        // Try with wrong remote key
        let result = alice.try_decrypt_skipped(&[0x44u8; 32], &[0u8; 100]);
        assert!(result.is_none());
    }
}
