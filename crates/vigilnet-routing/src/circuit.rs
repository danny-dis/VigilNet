//! Circuit management for onion routing with E2EE support
//!
//! This module provides the core circuit abstraction with optional
//! end-to-end encryption for all traffic using Double Ratchet.

use crate::{Result, RoutingError};
use std::time::Instant;
use tracing::{debug, error, info, instrument, trace, warn};
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
    #[instrument(level = "debug")]
    pub fn new(id: CircuitId) -> Self {
        trace!(circuit_id = id, "Creating new pending circuit");
        Self {
            id,
            hops_complete: 0,
            ephemeral_secrets: Vec::new(),
            session_keys: Vec::new(),
            peer_ids: Vec::new(),
        }
    }

    /// Add a hop's ephemeral secret
    #[instrument(skip(self, secret), level = "trace")]
    pub fn add_secret(&mut self, secret: vigilnet_crypto::keys::EphemeralSecret) {
        let index = self.ephemeral_secrets.len();
        trace!(hop_index = index, "Adding ephemeral secret");
        self.ephemeral_secrets.push(secret);
    }

    /// Add a peer ID for the next hop
    #[instrument(skip(self, peer_id), level = "trace")]
    pub fn add_peer(&mut self, peer_id: [u8; 32]) {
        trace!(peer_id = ?peer_id, "Adding peer to circuit");
        self.peer_ids.push(peer_id);
    }

    /// Complete a hop handshake
    #[instrument(skip(self, session_key), level = "debug")]
    pub fn complete_hop(&mut self, session_key: SessionKey) {
        let hop_num = self.hops_complete + 1;
        debug!(hop_num, "Completing hop handshake");
        self.session_keys.push(session_key);
        self.hops_complete += 1;
        trace!(total_hops = self.hops_complete, "Hop completed");
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
    #[instrument(level = "info")]
    pub fn new(id: CircuitId) -> Self {
        info!(circuit_id = id, "Creating new circuit");
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
    #[instrument(skip(self), level = "trace")]
    pub fn state(&self) -> &CircuitState {
        trace!(state = ?self.state, "Retrieving circuit state");
        &self.state
    }

    /// Get the number of hops
    #[instrument(skip(self), level = "trace")]
    pub fn hop_count(&self) -> usize {
        let count = self.hops.len();
        trace!(hop_count = count, "Retrieving hop count");
        count
    }

    /// Check if circuit is ready
    #[instrument(skip(self), level = "trace")]
    pub fn is_ready(&self) -> bool {
        let ready = self.state == CircuitState::Ready;
        trace!(is_ready = ready, "Checking circuit readiness");
        ready
    }

    /// Add a hop to the circuit
    #[instrument(skip(self, hop), level = "debug")]
    pub fn add_hop(&mut self, hop: CircuitHop) -> Result<()> {
        trace!(current_state = ?self.state, "Attempting to add hop");

        if self.state != CircuitState::Building && self.state != CircuitState::Extending {
            error!(current_state = ?self.state, "Cannot add hop in current state");
            return Err(RoutingError::Circuit("Cannot add hop in current state".into()));
        }

        self.hops.push(hop);
        debug!(
            hop_count = self.hops.len(),
            "Hop added to circuit"
        );
        Ok(())
    }

    /// Mark circuit as ready
    #[instrument(skip(self), level = "info")]
    pub fn set_ready(&mut self) {
        info!(
            circuit_id = self.id,
            hop_count = self.hops.len(),
            "Circuit marked as ready"
        );
        self.state = CircuitState::Ready;
    }

    /// Mark circuit as extending
    #[instrument(skip(self), level = "debug")]
    pub fn set_extending(&mut self) {
        debug!(circuit_id = self.id, "Circuit marked as extending");
        self.state = CircuitState::Extending;
    }

    /// Close the circuit
    #[instrument(skip(self), level = "info")]
    pub fn close(&mut self) {
        info!(
            circuit_id = self.id,
            bytes_sent = self.bytes_sent,
            bytes_received = self.bytes_received,
            age_secs = self.age_secs(),
            "Closing circuit"
        );
        self.state = CircuitState::Closed;
    }

    /// Get circuit age in seconds
    #[instrument(skip(self), level = "trace")]
    pub fn age_secs(&self) -> u64 {
        let age = self.created_at.elapsed().as_secs();
        trace!(circuit_id = self.id, age_secs = age, "Circuit age retrieved");
        age
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
    #[instrument(skip(self, shared_secret, remote_public), level = "info")]
    pub fn init_e2ee_initiator(&mut self, shared_secret: [u8; 32], remote_public: [u8; 32]) {
        info!(circuit_id = self.id, "Initializing E2EE as initiator");
        trace!("Creating send ratchet (initiator)");
        self.e2ee_send = Some(DoubleRatchet::initiator(shared_secret, remote_public));
        trace!("Creating receive ratchet (responder)");
        self.e2ee_recv = Some(DoubleRatchet::responder(shared_secret));
        info!(circuit_id = self.id, "E2EE initialized as initiator");
    }

    /// Initialize E2EE session as the circuit responder
    #[instrument(skip(self, shared_secret), level = "info")]
    pub fn init_e2ee_responder(&mut self, shared_secret: [u8; 32]) {
        info!(circuit_id = self.id, "Initializing E2EE as responder");
        trace!("Creating send ratchet (responder)");
        self.e2ee_send = Some(DoubleRatchet::responder(shared_secret));
        trace!("Creating receive ratchet (initiator)");
        self.e2ee_recv = Some(DoubleRatchet::initiator(shared_secret, [0u8; 32]));
        info!(circuit_id = self.id, "E2EE initialized as responder");
    }

    /// Check if E2EE is initialized
    #[instrument(skip(self), level = "trace")]
    pub fn has_e2ee(&self) -> bool {
        let has = self.e2ee_send.is_some() && self.e2ee_recv.is_some();
        trace!(circuit_id = self.id, has_e2ee = has, "Checked E2EE status");
        has
    }

    /// Encrypt a message with E2EE
    ///
    /// Even relay nodes cannot read this - they only forward encrypted blobs.
    #[instrument(skip(self, plaintext), level = "debug")]
    pub fn encrypt_e2ee(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        trace!(circuit_id = self.id, plaintext_len = plaintext.len(), "Encrypting E2EE message");

        let ratchet = self.e2ee_send.as_mut().ok_or_else(|| {
            error!(circuit_id = self.id, "E2EE not initialized for encryption");
            RoutingError::Crypto(vigilnet_crypto::CryptoError::RatchetError(
                "E2EE not initialized".to_string(),
            ))
        })?;

        let encrypted = ratchet.encrypt(plaintext)?;
        let encrypted_len = encrypted.ciphertext.len() as u64;
        self.bytes_sent += encrypted_len;

        debug!(
            circuit_id = self.id,
            plaintext_len = plaintext.len(),
            encrypted_len,
            total_bytes_sent = self.bytes_sent,
            "E2EE message encrypted"
        );

        Ok(encrypted.to_bytes())
    }

    /// Decrypt an E2EE encrypted message
    #[instrument(skip(self, ciphertext), level = "debug")]
    pub fn decrypt_e2ee(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        trace!(circuit_id = self.id, ciphertext_len = ciphertext.len(), "Decrypting E2EE message");

        let ratchet = self.e2ee_recv.as_mut().ok_or_else(|| {
            error!(circuit_id = self.id, "E2EE not initialized for decryption");
            RoutingError::Crypto(vigilnet_crypto::CryptoError::RatchetError(
                "E2EE not initialized".to_string(),
            ))
        })?;

        let encrypted = EncryptedMessage::from_bytes(ciphertext)?;
        let plaintext = ratchet.decrypt(&encrypted.header, &encrypted.ciphertext)?;
        self.bytes_received += ciphertext.len() as u64;

        debug!(
            circuit_id = self.id,
            ciphertext_len = ciphertext.len(),
            plaintext_len = plaintext.len(),
            total_bytes_received = self.bytes_received,
            "E2EE message decrypted"
        );

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
    #[instrument(skip(self, message), level = "info")]
    pub fn send_encrypted(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        info!(
            circuit_id = self.id,
            message_len = message.len(),
            "Sending encrypted message through circuit"
        );
        self.encrypt_e2ee(message)
    }

    /// Receive and decrypt message from circuit
    ///
    /// Decrypts E2EE layer after passing through onion layers.
    #[instrument(skip(self, encrypted), level = "info")]
    pub fn receive_encrypted(&mut self, encrypted: &[u8]) -> Result<Vec<u8>> {
        info!(
            circuit_id = self.id,
            encrypted_len = encrypted.len(),
            "Receiving encrypted message from circuit"
        );
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
        circuit.add_hop(hop).expect("Failed to add hop to circuit");
        assert_eq!(circuit.hop_count(), 1);

        circuit.set_ready();
        assert!(circuit.is_ready());

        circuit.close();
        assert_eq!(circuit.state(), &CircuitState::Closed);
    }
}
