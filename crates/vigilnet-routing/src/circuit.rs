//! Circuit management for onion routing with E2EE support
//!
//! This module provides the core circuit abstraction with optional
//! end-to-end encryption for all traffic using Double Ratchet.

use crate::{Result, RoutingError};
use std::time::Instant;
use vigilnet_crypto::ratchet::{DoubleRatchet, EncryptedMessage};
use vigilnet_crypto::SessionKey;

/// Unique identifier for a circuit
pub type CircuitId = u32;

/// State of a circuit
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitState {
    /// Circuit is being created
    Building,
    /// Circuit is ready for use
    Ready,
    /// Circuit is being extended
    Extending,
    /// Circuit is closing
    Closing,
    /// Circuit is closed
    Closed,
}

/// A hop in the circuit
#[derive(Clone)]
pub struct CircuitHop {
    /// Peer ID of this hop
    pub peer_id: [u8; 32],
    /// Session key for this hop
    pub session_key: SessionKey,
    /// Whether this is an exit node
    pub is_exit: bool,
}

/// Pending circuit during handshake
pub struct PendingCircuit {
    /// Circuit ID
    pub id: CircuitId,
    /// Number of hops completed so far
    pub hops_complete: usize,
    /// Our ephemeral DH secrets for each hop
    pub ephemeral_secrets: Vec<vigilnet_crypto::keys::EphemeralSecret>,
    /// Established session keys
    pub session_keys: Vec<SessionKey>,
    /// Peer IDs of hops
    pub peer_ids: Vec<[u8; 32]>,
}

impl PendingCircuit {
    /// Create a new pending circuit
    pub fn new(id: CircuitId) -> Self {
        Self {
            id,
            hops_complete: 0,
            ephemeral_secrets: Vec::new(),
            session_keys: Vec::new(),
            peer_ids: Vec::new(),
        }
    }

    /// Add a hop's ephemeral secret
    pub fn add_secret(&mut self, secret: vigilnet_crypto::keys::EphemeralSecret) {
        self.ephemeral_secrets.push(secret);
    }

    /// Add a peer ID for the next hop
    pub fn add_peer(&mut self, peer_id: [u8; 32]) {
        self.peer_ids.push(peer_id);
    }

    /// Complete a hop handshake
    pub fn complete_hop(&mut self, session_key: SessionKey) {
        self.session_keys.push(session_key);
        self.hops_complete += 1;
    }
}

/// An onion routing circuit
pub struct Circuit {
    /// Unique circuit ID
    pub id: CircuitId,
    /// Circuit hops (entry, middle, ..., exit)
    hops: Vec<CircuitHop>,
    /// Current state
    state: CircuitState,
    /// When the circuit was created
    created_at: Instant,
    /// Bytes sent through this circuit
    bytes_sent: u64,
    /// Bytes received through this circuit
    bytes_received: u64,
    /// E2EE Double Ratchet for sending
    e2ee_send: Option<DoubleRatchet>,
    /// E2EE Double Ratchet for receiving
    e2ee_recv: Option<DoubleRatchet>,
}

impl Circuit {
    /// Create a new circuit with the given ID
    pub fn new(id: CircuitId) -> Self {
        Self {
            id,
            hops: Vec::new(),
            state: CircuitState::Building,
            created_at: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            e2ee_send: None,
            e2ee_recv: None,
        }
    }

    /// Get the circuit state
    pub fn state(&self) -> &CircuitState {
        &self.state
    }

    /// Get the number of hops
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// Check if circuit is ready
    pub fn is_ready(&self) -> bool {
        self.state == CircuitState::Ready
    }

    /// Add a hop to the circuit
    pub fn add_hop(&mut self, hop: CircuitHop) -> Result<()> {
        if self.state != CircuitState::Building && self.state != CircuitState::Extending {
            return Err(RoutingError::Circuit("Cannot add hop in current state".into()));
        }
        self.hops.push(hop);
        Ok(())
    }

    /// Mark circuit as ready
    pub fn set_ready(&mut self) {
        self.state = CircuitState::Ready;
    }

    /// Mark circuit as extending
    pub fn set_extending(&mut self) {
        self.state = CircuitState::Extending;
    }

    /// Close the circuit
    pub fn close(&mut self) {
        self.state = CircuitState::Closed;
    }

    /// Get circuit age in seconds
    pub fn age_secs(&self) -> u64 {
        self.created_at.elapsed().as_secs()
    }

    /// Get all session keys for onion encryption
    pub fn session_keys(&self) -> Vec<&SessionKey> {
        self.hops.iter().map(|h| &h.session_key).collect()
    }

    /// Update bytes sent
    pub fn add_bytes_sent(&mut self, bytes: u64) {
        self.bytes_sent += bytes;
    }

    /// Update bytes received
    pub fn add_bytes_received(&mut self, bytes: u64) {
        self.bytes_received += bytes;
    }

    /// Get total bytes transferred
    pub fn bytes_transferred(&self) -> (u64, u64) {
        (self.bytes_sent, self.bytes_received)
    }

    /// Initialize E2EE session as the circuit initiator
    pub fn init_e2ee_initiator(&mut self, shared_secret: [u8; 32], remote_public: [u8; 32]) {
        self.e2ee_send = Some(DoubleRatchet::initiator(shared_secret, remote_public));
        self.e2ee_recv = Some(DoubleRatchet::responder(shared_secret));
    }

    /// Initialize E2EE session as the circuit responder
    pub fn init_e2ee_responder(&mut self, shared_secret: [u8; 32]) {
        self.e2ee_send = Some(DoubleRatchet::responder(shared_secret));
        self.e2ee_recv = Some(DoubleRatchet::initiator(shared_secret, [0u8; 32]));
    }

    /// Check if E2EE is initialized
    pub fn has_e2ee(&self) -> bool {
        self.e2ee_send.is_some() && self.e2ee_recv.is_some()
    }

    /// Encrypt a message with E2EE
    ///
    /// Even relay nodes cannot read this - they only forward encrypted blobs.
    pub fn encrypt_e2ee(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let ratchet = self.e2ee_send.as_mut().ok_or_else(|| {
            RoutingError::Crypto(vigilnet_crypto::CryptoError::RatchetError(
                "E2EE not initialized".to_string(),
            ))
        })?;

        let encrypted = ratchet.encrypt(plaintext)?;
        self.bytes_sent += encrypted.ciphertext.len() as u64;
        Ok(encrypted.to_bytes())
    }

    /// Decrypt an E2EE encrypted message
    pub fn decrypt_e2ee(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let ratchet = self.e2ee_recv.as_mut().ok_or_else(|| {
            RoutingError::Crypto(vigilnet_crypto::CryptoError::RatchetError(
                "E2EE not initialized".to_string(),
            ))
        })?;

        let encrypted = EncryptedMessage::from_bytes(ciphertext)?;
        let plaintext = ratchet.decrypt(&encrypted.header, &encrypted.ciphertext)?;
        self.bytes_received += ciphertext.len() as u64;
        Ok(plaintext)
    }

    /// Process incoming DH public key for E2EE ratchet
    pub fn process_e2ee_dh(&mut self, peer_public: &[u8; 32]) -> Result<()> {
        if let Some(ref mut ratchet) = self.e2ee_recv {
            ratchet.dh_ratchet(peer_public)?;
        }
        Ok(())
    }

    /// Get current E2EE sending public key
    pub fn e2ee_sending_key(&self) -> Option<[u8; 32]> {
        self.e2ee_send.as_ref().map(|r| r.sending_public_key())
    }

    /// Send encrypted message through the circuit
    ///
    /// The message is E2EE encrypted, then sent through onion layers.
    /// Relay nodes see only encrypted blobs they cannot decrypt.
    pub fn send_encrypted(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_e2ee(message)
    }

    /// Receive and decrypt message from circuit
    ///
    /// Decrypts E2EE layer after passing through onion layers.
    pub fn receive_encrypted(&mut self, encrypted: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_e2ee(encrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_lifecycle() {
        let mut circuit = Circuit::new(1);
        assert_eq!(circuit.state(), &CircuitState::Building);

        let hop = CircuitHop {
            peer_id: [1u8; 32],
            session_key: SessionKey::from_shared_secret([1u8; 32]),
            is_exit: false,
        };
        circuit.add_hop(hop).unwrap();
        assert_eq!(circuit.hop_count(), 1);

        circuit.set_ready();
        assert!(circuit.is_ready());

        circuit.close();
        assert_eq!(circuit.state(), &CircuitState::Closed);
    }
}
