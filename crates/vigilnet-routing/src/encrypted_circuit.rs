//! Encrypted Circuit - E2EE wrapper around onion routing circuit
//!
//! This module provides end-to-end encryption for all circuit traffic using
//! the Signal Protocol's Double Ratchet algorithm. Even relay nodes in the
//! network cannot read the traffic they forward.

use vigilnet_crypto::ratchet::{DoubleRatchet, EncryptedMessage, MessageHeader};

use crate::{Circuit, CircuitHop, CircuitId, Result, RoutingError};

/// An encrypted circuit that provides E2EE for all traffic
///
/// Even relay nodes cannot read the traffic - they only see encrypted blobs.
/// The Double Ratchet provides forward secrecy and break-in recovery.
pub struct EncryptedCircuit {
    /// The underlying onion routing circuit
    circuit: Circuit,
    /// Our Double Ratchet state (for sending)
    ratchet_send: Option<DoubleRatchet>,
    /// Peer's Double Ratchet state (for receiving)
    ratchet_recv: Option<DoubleRatchet>,
    /// Remote peer's public key for initial ratchet
    remote_public_key: Option<[u8; 32]>,
    /// Shared secret for Double Ratchet initialization
    shared_secret: Option<[u8; 32]>,
    /// Whether we're the initiator of the E2EE session
    is_initiator: bool,
    /// Messages in flight waiting for DH ratchet
    pending_messages: Vec<PendingMessage>,
}

struct PendingMessage {
    encrypted: EncryptedMessage,
    ciphertext: Vec<u8>,
}

impl EncryptedCircuit {
    /// Create a new encrypted circuit from an existing circuit
    pub fn new(circuit: Circuit) -> Self {
        Self {
            circuit,
            ratchet_send: None,
            ratchet_recv: None,
            remote_public_key: None,
            shared_secret: None,
            is_initiator: false,
            pending_messages: Vec::new(),
        }
    }

    /// Initialize E2EE as the circuit initiator (client)
    ///
    /// The first hop's session key is used as the shared secret for
    /// Double Ratchet initialization.
    pub fn init_as_initiator(&mut self, shared_secret: [u8; 32], remote_public_key: [u8; 32]) {
        self.shared_secret = Some(shared_secret);
        self.remote_public_key = Some(remote_public_key);
        self.is_initiator = true;
    }

    /// Initialize E2EE as the responder (relay/exit node)
    pub fn init_as_responder(&mut self, shared_secret: [u8; 32]) {
        self.shared_secret = Some(shared_secret);
        self.is_initiator = false;
    }

    /// Establish the Double Ratchet session
    pub fn establish_session(&mut self) -> Result<()> {
        let shared = self.shared_secret.ok_or_else(|| {
            RoutingError::Crypto(vigilnet_crypto::CryptoError::RatchetError(
                "No shared secret set".to_string(),
            ))
        })?;

        if self.is_initiator {
            let remote_pk = self.remote_public_key.ok_or_else(|| {
                RoutingError::Crypto(vigilnet_crypto::CryptoError::RatchetError(
                    "No remote public key set".to_string(),
                ))
            })?;

            self.ratchet_send = Some(DoubleRatchet::initiator(shared, remote_pk));
            self.ratchet_recv = Some(DoubleRatchet::responder(shared));
        } else {
            self.ratchet_send = Some(DoubleRatchet::responder(shared));
            self.ratchet_recv = Some(DoubleRatchet::initiator(shared, [0u8; 32]));
        }

        Ok(())
    }

    /// Process incoming DH public key from peer to advance ratchet
    pub fn process_dh_public_key(&mut self, peer_public_key: &[u8; 32]) -> Result<()> {
        if let Some(ref mut ratchet) = self.ratchet_recv {
            ratchet.dh_ratchet(peer_public_key)?;
        }
        Ok(())
    }

    /// Encrypt a message for end-to-end transmission
    ///
    /// Even though the circuit uses onion routing layers, this provides
    /// an additional E2EE layer that even relay nodes cannot decrypt.
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Result<EncryptedCircuitMessage> {
        let ratchet = self.ratchet_send.as_mut().ok_or_else(|| {
            RoutingError::Crypto(vigilnet_crypto::CryptoError::RatchetError(
                "Session not established".to_string(),
            ))
        })?;

        let encrypted = ratchet.encrypt(plaintext)?;

        let ciphertext = encrypted.to_bytes();
        self.circuit.add_bytes_sent(ciphertext.len() as u64);

        Ok(EncryptedCircuitMessage {
            encrypted_message: encrypted,
            ciphertext,
        })
    }

    /// Decrypt an end-to-end encrypted message
    pub fn decrypt_message(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let ratchet = self.ratchet_recv.as_mut().ok_or_else(|| {
            RoutingError::Crypto(vigilnet_crypto::CryptoError::RatchetError(
                "Session not established".to_string(),
            ))
        })?;

        let encrypted = EncryptedMessage::from_bytes(ciphertext)?;
        let plaintext = ratchet.decrypt(&encrypted.header, &encrypted.ciphertext)?;

        self.circuit.add_bytes_received(ciphertext.len() as u64);

        Ok(plaintext)
    }

    /// Encrypt a message and wrap it for circuit transport
    ///
    /// Returns encrypted payload that can be sent through the circuit.
    /// The relay nodes will see only encrypted blobs they cannot read.
    pub fn wrap_for_transport(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let circuit_msg = self.encrypt_message(payload)?;
        Ok(circuit_msg.ciphertext)
    }

    /// Unwrap and decrypt a message from circuit transport
    pub fn unwrap_from_transport(&mut self, encrypted_payload: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_message(encrypted_payload)
    }

    /// Get the current sending public key for the Double Ratchet
    ///
    /// This should be sent to the peer via the circuit.
    pub fn current_sending_key(&self) -> Option<[u8; 32]> {
        self.ratchet_send.as_ref().map(|r| r.sending_public_key())
    }

    /// Get the circuit ID
    pub fn id(&self) -> CircuitId {
        self.circuit.id
    }

    /// Get the number of hops in the underlying circuit
    pub fn hop_count(&self) -> usize {
        self.circuit.hop_count()
    }

    /// Check if the circuit is ready for traffic
    pub fn is_ready(&self) -> bool {
        self.circuit.is_ready() && self.ratchet_send.is_some() && self.ratchet_recv.is_some()
    }

    /// Get session keys from the underlying circuit for onion layers
    pub fn session_keys(&self) -> Vec<&vigilnet_crypto::SessionKey> {
        self.circuit.session_keys()
    }

    /// Get all hops from the underlying circuit
    pub fn hops(&self) -> &[CircuitHop] {
        &self.circuit.hops
    }

    /// Close the encrypted circuit
    pub fn close(&mut self) {
        self.circuit.close();
    }

    /// Get circuit age in seconds
    pub fn age_secs(&self) -> u64 {
        self.circuit.age_secs()
    }

    /// Get bytes transferred statistics
    pub fn bytes_transferred(&self) -> (u64, u64) {
        self.circuit.bytes_transferred()
    }

    /// Consume and return the underlying circuit
    pub fn into_inner(self) -> Circuit {
        self.circuit
    }
}

/// Encrypted message ready for circuit transport
pub struct EncryptedCircuitMessage {
    /// The encrypted message with header
    pub encrypted_message: EncryptedMessage,
    /// Serialized ciphertext for transport
    pub ciphertext: Vec<u8>,
}

impl EncryptedCircuitMessage {
    /// Create from raw ciphertext
    pub fn from_ciphertext(ciphertext: Vec<u8>) -> Result<Self> {
        let encrypted_message = EncryptedMessage::from_bytes(&ciphertext)?;
        Ok(Self {
            encrypted_message,
            ciphertext,
        })
    }

    /// Get the message header
    pub fn header(&self) -> &MessageHeader {
        &self.encrypted_message.header
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_circuit_creation() {
        let circuit = Circuit::new(42);
        let encrypted = EncryptedCircuit::new(circuit);
        
        assert_eq!(encrypted.id(), 42);
        assert!(!encrypted.is_ready());
    }

    #[test]
    fn test_e2e_encryption_roundtrip() {
        let mut alice_circuit = Circuit::new(1);
        let mut bob_circuit = Circuit::new(2);

        let shared_secret = [0x42u8; 32];
        let bob_public = [0x43u8; 32];

        alice_circuit.set_ready();
        bob_circuit.set_ready();

        let mut alice = EncryptedCircuit::new(alice_circuit);
        let mut bob = EncryptedCircuit::new(bob_circuit);

        alice.init_as_initiator(shared_secret, bob_public);
        bob.init_as_responder(shared_secret);

        alice.establish_session().unwrap();
        bob.establish_session().unwrap();

        bob.process_dh_public_key(&alice.current_sending_key().unwrap()).unwrap();
        alice.process_dh_public_key(&bob.current_sending_key().unwrap()).unwrap();

        let plaintext = b"Hello, secure world!";
        
        let encrypted = alice.wrap_for_transport(plaintext).unwrap();
        let decrypted = bob.unwrap_from_transport(&encrypted).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_relay_cannot_read_traffic() {
        let mut alice_circuit = Circuit::new(1);
        alice_circuit.set_ready();

        let shared_secret = [0x42u8; 32];
        let bob_public = [0x43u8; 32];

        let mut alice = EncryptedCircuit::new(alice_circuit);
        alice.init_as_initiator(shared_secret, bob_public);
        alice.establish_session().unwrap();

        let plaintext = b"Secret message that relay cannot read";
        let encrypted_blob = alice.wrap_for_transport(plaintext).unwrap();

        let mut fake_relay = EncryptedCircuit::new(Circuit::new(99));
        fake_relay.init_as_responder([0x99u8; 32]);
        fake_relay.establish_session().unwrap();

        let result = fake_relay.unwrap_from_transport(&encrypted_blob);
        assert!(result.is_err() || result.unwrap() != plaintext.to_vec());
    }
}
