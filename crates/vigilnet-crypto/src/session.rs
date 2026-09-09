//! Session Management for Signal Protocol E2EE
//!
//! Manages session state, creation from X3DH, and message encryption/decryption

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::{
    ratchet::{DoubleRatchet, EncryptedMessage, MessageHeader},
    x3dh::{IdentityKeyPair, OneTimePreKey, PreKeyBundle, SignedPreKey, X3DH},
    CryptoError, Result,
};

/// Session role
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum SessionRole {
    Initiator,
    Responder,
}

/// Session direction
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum SessionDirection {
    AgentToAgent,
    CircleEncryption,
}

/// Session state for persistence
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionState {
    pub session_id: String,
    pub peer_identity: [u8; 32],
    pub role: SessionRole,
    pub direction: SessionDirection,
    pub created_at: u64,
    pub last_used_at: u64,
    pub message_count: u32,
    pub ratchet_state: crate::ratchet::RatchetState,
}

/// Encrypted session message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionMessage {
    pub session_id: String,
    pub message_type: MessageType,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MessageType {
    X3DHPreKey {
        identity_key: [u8; 32],
        ephemeral_key: [u8; 32],
        spk_id: u32,
        otpk_id: Option<u32>,
    },
    X3DHResponse,
    RatchetMessage(EncryptedMessage),
    PreKeyRequest,
}

/// Complete session for E2EE communication
pub struct Session {
    session_id: String,
    peer_identity: [u8; 32],
    role: SessionRole,
    direction: SessionDirection,
    created_at: u64,
    last_used_at: u64,
    message_count: u32,
    ratchet: DoubleRatchet,
}

impl Session {
    /// Create a new session as initiator (Alice) using a pre-key bundle
    pub fn create_initiator(
        bundle: &PreKeyBundle,
        peer_identity: [u8; 32],
    ) -> Result<(Self, SessionMessage)> {
        debug!("Creating session as initiator");

        let session_id = Self::generate_session_id();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| CryptoError::SessionError(format!("System time error: {}", e)))?
            .as_secs();

        let (x3dh_state, shared_secret, x3dh_message) =
            X3DH::initiator_initiate(bundle)?;

        let mut ratchet = DoubleRatchet::initiator(
            shared_secret,
            bundle.signed_prekey.public,
        )?;

        let ratchet_init = ratchet.encrypt(b"")?;
        let ratchet_header = ratchet_init.header.clone();

        let payload = Self::encode_prekey_message(
            x3dh_message,
            ratchet_header,
            &bundle.signed_prekey,
            bundle.one_time_prekey.as_ref(),
        );

        let session = Self {
            session_id: session_id.clone(),
            peer_identity,
            role: SessionRole::Initiator,
            direction: SessionDirection::AgentToAgent,
            created_at: now,
            last_used_at: now,
            message_count: 0,
            ratchet,
        };

        info!("Initiator session created: {}", session_id);

        let message = SessionMessage {
            session_id,
            message_type: MessageType::X3DHPreKey {
                identity_key: x3dh_message[0..32].try_into()
                    .map_err(|_| CryptoError::InvalidMessage("Invalid identity key length".to_string()))?,
                ephemeral_key: x3dh_message[32..64].try_into()
                    .map_err(|_| CryptoError::InvalidMessage("Invalid ephemeral key length".to_string()))?,
                spk_id: bundle.signed_prekey.id,
                otpk_id: bundle.one_time_prekey.as_ref().map(|otpk| otpk.id),
            },
            payload,
        };

        Ok((session, message))
    }

    /// Create a new session as responder (Bob)
    pub fn create_responder(
        identity_key: &IdentityKeyPair,
        signed_prekey: &SignedPreKey,
        one_time_prekey: Option<&OneTimePreKey>,
        initiator_identity: [u8; 32],
        initiator_ephemeral: [u8; 32],
        spk_id: u32,
        otpk_id: Option<u32>,
    ) -> Result<Self> {
        debug!("Creating session as responder");

        if signed_prekey.id != spk_id {
            return Err(CryptoError::SessionError("SPK ID mismatch".to_string()));
        }

        let session_id = Self::generate_session_id();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| CryptoError::SessionError(format!("System time error: {}", e)))?
            .as_secs();

        let shared_secret = X3DH::responder_initiate(
            identity_key,
            signed_prekey,
            one_time_prekey,
            initiator_identity,
            initiator_ephemeral,
        )?;

        let mut ratchet = DoubleRatchet::responder(shared_secret);

        ratchet.dh_ratchet(&initiator_ephemeral)?;

        let session = Self {
            session_id,
            peer_identity: initiator_identity,
            role: SessionRole::Responder,
            direction: SessionDirection::AgentToAgent,
            created_at: now,
            last_used_at: now,
            message_count: 0,
            ratchet,
        };

        info!("Responder session created");

        Ok(session)
    }

    /// Create a circle encryption session (symmetric key based)
    pub fn create_circle_session(
        circle_key: [u8; 32],
        peer_identity: [u8; 32],
    ) -> Result<Self> {
        debug!("Creating circle encryption session");

        let session_id = Self::generate_session_id();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| CryptoError::SessionError(format!("System time error: {}", e)))?
            .as_secs();

        let ratchet = DoubleRatchet::initiator(circle_key, peer_identity)?;

        Ok(Self {
            session_id,
            peer_identity,
            role: SessionRole::Initiator,
            direction: SessionDirection::CircleEncryption,
            created_at: now,
            last_used_at: now,
            message_count: 0,
            ratchet,
        })
    }

    /// Encrypt a message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<SessionMessage> {
        let encrypted = self.ratchet.encrypt(plaintext)?;
        
        self.message_count += 1;
        self.last_used_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| CryptoError::SessionError(format!("System time error: {}", e)))?
            .as_secs();

        Ok(SessionMessage {
            session_id: self.session_id.clone(),
            message_type: MessageType::RatchetMessage(encrypted),
            payload: encrypted.ciphertext,
        })
    }

    /// Decrypt a message
    pub fn decrypt(&mut self, message: &SessionMessage) -> Result<Vec<u8>> {
        if message.session_id != self.session_id {
            return Err(CryptoError::SessionError("Session ID mismatch".to_string()));
        }

        let encrypted = match &message.message_type {
            MessageType::RatchetMessage(em) => em.clone(),
            _ => return Err(CryptoError::InvalidMessage("Not a ratchet message".to_string())),
        };

        let plaintext = self.ratchet.decrypt(&encrypted.header, &encrypted.ciphertext)?;

        self.message_count += 1;
        self.last_used_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| CryptoError::SessionError(format!("System time error: {}", e)))?
            .as_secs();

        Ok(plaintext)
    }

    /// Process an incoming ratchet message (handles out-of-order)
    pub fn process_message(&mut self, encrypted: &EncryptedMessage) -> Result<Vec<u8>> {
        if let Some(remote_key) = encrypted.header.public_key {
            if let Some(current_key) = self.ratchet.state().remote_ratchet_key {
                if remote_key != current_key {
                    self.ratchet.dh_ratchet(&remote_key)?;
                }
            } else {
                self.ratchet.dh_ratchet(&remote_key)?;
            }
        }

        let plaintext = self.ratchet.decrypt(&encrypted.header, &encrypted.ciphertext)?;

        self.message_count += 1;
        self.last_used_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| CryptoError::SessionError(format!("System time error: {}", e)))?
            .as_secs();

        Ok(plaintext)
    }

    /// Get session state for storage
    pub fn state(&self) -> SessionState {
        SessionState {
            session_id: self.session_id.clone(),
            peer_identity: self.peer_identity,
            role: self.role,
            direction: self.direction,
            created_at: self.created_at,
            last_used_at: self.last_used_at,
            message_count: self.message_count,
            ratchet_state: self.ratchet.state().clone(),
        }
    }

    /// Restore session from state
    pub fn from_state(state: SessionState) -> Result<Self> {
        use crate::ratchet::RatchetKeyPair;

        let ratchet = match state.role {
            SessionRole::Initiator => {
                if let Some(remote_key) = state.ratchet_state.remote_ratchet_key {
                    DoubleRatchet::initiator(state.ratchet_state.root_key, remote_key)?
                } else {
                    return Err(CryptoError::SessionError(
                        "Initiator requires remote ratchet key".to_string(),
                    ));
                }
            }
            SessionRole::Responder => DoubleRatchet::responder(state.ratchet_state.root_key),
        };

        Ok(Self {
            session_id: state.session_id,
            peer_identity: state.peer_identity,
            role: state.role,
            direction: state.direction,
            created_at: state.created_at,
            last_used_at: state.last_used_at,
            message_count: state.message_count,
            ratchet,
        })
    }

    /// Get session ID
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Get peer identity
    pub fn peer_identity(&self) -> [u8; 32] {
        self.peer_identity
    }

    /// Get message count
    pub fn message_count(&self) -> u32 {
        self.message_count
    }

    /// Get session role
    pub fn role(&self) -> SessionRole {
        self.role
    }

    /// Get session direction
    pub fn direction(&self) -> SessionDirection {
        self.direction
    }

    fn generate_session_id() -> String {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    fn encode_prekey_message(
        x3dh_message: Vec<u8>,
        ratchet_header: MessageHeader,
        spk: &SignedPreKey,
        otpk: Option<&OneTimePreKey>,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        
        payload.extend_from_slice(&spk.id.to_le_bytes());
        if let Some(otpk) = otpk {
            payload.extend_from_slice(&1u8.to_le_bytes());
            payload.extend_from_slice(&otpk.id.to_le_bytes());
        } else {
            payload.extend_from_slice(&0u8.to_le_bytes());
        }

        payload.extend_from_slice(&ratchet_header.previous_chain_length.to_le_bytes());
        payload.extend_from_slice(&ratchet_header.message_number.to_le_bytes());
        
        if let Some(ref pk) = ratchet_header.public_key {
            payload.extend_from_slice(pk);
        }

        payload
    }
}

/// Serialize session message to bytes
pub fn serialize_message(msg: &SessionMessage) -> Result<Vec<u8>> {
    serde_json::to_vec(msg).map_err(|e| CryptoError::SessionError(e.to_string()))
}

/// Deserialize session message from bytes
pub fn deserialize_message(data: &[u8]) -> Result<SessionMessage> {
    serde_json::from_slice(data).map_err(|e| CryptoError::SessionError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_bundle() -> (IdentityKeyPair, SignedPreKey, OneTimePreKey, PreKeyBundle) {
        let bob_ik = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(&bob_ik, 1);
        let bob_otpk = OneTimePreKey::generate(1);

        let bundle = PreKeyBundle {
            identity_key: bob_ik.identity_public,
            signed_prekey: bob_spk.clone(),
            one_time_prekey: Some(bob_otpk.clone()),
        };

        (bob_ik, bob_spk, bob_otpk, bundle)
    }

    fn extract_prekey_data(msg: &SessionMessage) -> ([u8; 32], [u8; 32], u32, Option<u32>) {
        if let MessageType::X3DHPreKey { 
            identity_key, 
            ephemeral_key, 
            spk_id, 
            otpk_id 
        } = &msg.message_type {
            (*identity_key, *ephemeral_key, *spk_id, *otpk_id)
        } else {
            panic!("Expected prekey message");
        }
    }

    #[test]
    fn test_session_creation_and_encryption() {
        let (bob_ik, bob_spk, bob_otpk, bundle) = create_test_bundle();

        let (mut alice_session, alice_msg) =
            Session::create_initiator(&bundle, bob_ik.identity_public).unwrap();

        let (identity_key, ephemeral_key, spk_id, otpk_id) = extract_prekey_data(&alice_msg);

        let mut bob_session = Session::create_responder(
            &bob_ik,
            &bob_spk,
            Some(&bob_otpk),
            identity_key,
            ephemeral_key,
            spk_id,
            otpk_id,
        )
        .unwrap();

        let plaintext = b"Hello, secure world!";
        let encrypted = alice_session.encrypt(plaintext).unwrap();
        let decrypted = bob_session.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_circle_session() {
        let circle_key = [0x42u8; 32];
        let peer_identity = [0x43u8; 32];

        let mut session = Session::create_circle_session(circle_key, peer_identity);

        let plaintext = b"Circle message";
        let encrypted = session.encrypt(plaintext).unwrap();
        
        assert_eq!(session.message_count(), 1);
        assert_eq!(session.direction(), SessionDirection::CircleEncryption);
        assert_eq!(session.role(), SessionRole::Initiator);
    }

    #[test]
    fn test_session_state_persistence() {
        let (bob_ik, bob_spk, bob_otpk, bundle) = create_test_bundle();

        let (mut alice_session, alice_msg) =
            Session::create_initiator(&bundle, bob_ik.identity_public).unwrap();

        let (identity_key, ephemeral_key, spk_id, otpk_id) = extract_prekey_data(&alice_msg);

        let mut bob_session = Session::create_responder(
            &bob_ik,
            &bob_spk,
            Some(&bob_otpk),
            identity_key,
            ephemeral_key,
            spk_id,
            otpk_id,
        )
        .unwrap();

        let plaintext = b"Hello, world!";
        alice_session.encrypt(plaintext).unwrap();
        alice_session.encrypt(b"Second message").unwrap();

        let state = alice_session.state();
        
        let serialized = serde_json::to_vec(&state).unwrap();
        let restored_state: SessionState = serde_json::from_slice(&serialized).unwrap();
        
        let restored = Session::from_state(restored_state).unwrap();
        
        assert_eq!(restored.session_id(), alice_session.session_id());
        assert_eq!(restored.message_count(), alice_session.message_count());
    }

    #[test]
    fn test_bidirectional_encryption() {
        let (bob_ik, bob_spk, bob_otpk, bundle) = create_test_bundle();

        let (mut alice_session, alice_msg) =
            Session::create_initiator(&bundle, bob_ik.identity_public).unwrap();

        let (identity_key, ephemeral_key, spk_id, otpk_id) = extract_prekey_data(&alice_msg);

        let mut bob_session = Session::create_responder(
            &bob_ik,
            &bob_spk,
            Some(&bob_otpk),
            identity_key,
            ephemeral_key,
            spk_id,
            otpk_id,
        )
        .unwrap();

        let alice_to_bob = b"Alice to Bob";
        let encrypted = alice_session.encrypt(alice_to_bob).unwrap();
        let decrypted = bob_session.decrypt(&encrypted).unwrap();
        assert_eq!(alice_to_bob.as_slice(), decrypted.as_slice());

        let bob_to_alice = b"Bob to Alice";
        let encrypted = bob_session.encrypt(bob_to_alice).unwrap();
        let decrypted = alice_session.decrypt(&encrypted).unwrap();
        assert_eq!(bob_to_alice.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_message_serialization() {
        let (bob_ik, bob_spk, bob_otpk, bundle) = create_test_bundle();

        let (_alice_session, alice_msg) =
            Session::create_initiator(&bundle, bob_ik.identity_public).unwrap();

        let serialized = serialize_message(&alice_msg).unwrap();
        let deserialized = deserialize_message(&serialized).unwrap();

        assert_eq!(alice_msg.session_id, deserialized.session_id);
        match (&alice_msg.message_type, &deserialized.message_type) {
            (MessageType::X3DHPreKey { spk_id: id1, .. }, MessageType::X3DHPreKey { spk_id: id2, .. }) => {
                assert_eq!(id1, id2);
            }
            _ => panic!("Message type mismatch"),
        }
    }

    #[test]
    fn test_invalid_session_id() {
        let (bob_ik, bob_spk, bob_otpk, bundle) = create_test_bundle();

        let (mut alice_session, _alice_msg) =
            Session::create_initiator(&bundle, bob_ik.identity_public).unwrap();

        let invalid_message = SessionMessage {
            session_id: "invalid-session-id".to_string(),
            message_type: MessageType::RatchetMessage(
                crate::ratchet::EncryptedMessage {
                    header: crate::ratchet::MessageHeader {
                        public_key: None,
                        previous_chain_length: 0,
                        message_number: 0,
                    },
                    ciphertext: vec![],
                }
            ),
            payload: vec![],
        };

        let result = alice_session.decrypt(&invalid_message);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_without_otpk() {
        let bob_ik = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(&bob_ik, 1);

        let bundle = PreKeyBundle {
            identity_key: bob_ik.identity_public,
            signed_prekey: bob_spk.clone(),
            one_time_prekey: None,
        };

        let (mut alice_session, alice_msg) =
            Session::create_initiator(&bundle, bob_ik.identity_public).unwrap();

        let (identity_key, ephemeral_key, spk_id, otpk_id) = extract_prekey_data(&alice_msg);
        assert!(otpk_id.is_none());

        let mut bob_session = Session::create_responder(
            &bob_ik,
            &bob_spk,
            None,
            identity_key,
            ephemeral_key,
            spk_id,
            otpk_id,
        )
        .unwrap();

        let plaintext = b"No OTPK test";
        let encrypted = alice_session.encrypt(plaintext).unwrap();
        let decrypted = bob_session.decrypt(&encrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_session_multiple_messages() {
        let (bob_ik, bob_spk, bob_otpk, bundle) = create_test_bundle();

        let (mut alice_session, alice_msg) =
            Session::create_initiator(&bundle, bob_ik.identity_public).unwrap();

        let (identity_key, ephemeral_key, spk_id, otpk_id) = extract_prekey_data(&alice_msg);

        let mut bob_session = Session::create_responder(
            &bob_ik,
            &bob_spk,
            Some(&bob_otpk),
            identity_key,
            ephemeral_key,
            spk_id,
            otpk_id,
        )
        .unwrap();

        for i in 0..50 {
            let msg = format!("Message number {}", i);
            let encrypted = alice_session.encrypt(msg.as_bytes()).unwrap();
            let decrypted = bob_session.decrypt(&encrypted).unwrap();
            assert_eq!(msg.as_bytes(), decrypted.as_slice());
        }

        assert_eq!(alice_session.message_count(), 50);
        assert_eq!(bob_session.message_count(), 50);
    }

    #[test]
    fn test_session_alternating_directions() {
        let (bob_ik, bob_spk, bob_otpk, bundle) = create_test_bundle();

        let (mut alice_session, alice_msg) =
            Session::create_initiator(&bundle, bob_ik.identity_public).unwrap();

        let (identity_key, ephemeral_key, spk_id, otpk_id) = extract_prekey_data(&alice_msg);

        let mut bob_session = Session::create_responder(
            &bob_ik,
            &bob_spk,
            Some(&bob_otpk),
            identity_key,
            ephemeral_key,
            spk_id,
            otpk_id,
        )
        .unwrap();

        for i in 0..20 {
            if i % 2 == 0 {
                let msg = format!("Alice: {}", i);
                let encrypted = alice_session.encrypt(msg.as_bytes()).unwrap();
                let decrypted = bob_session.decrypt(&encrypted).unwrap();
                assert_eq!(msg.as_bytes(), decrypted.as_slice());
            } else {
                let msg = format!("Bob: {}", i);
                let encrypted = bob_session.encrypt(msg.as_bytes()).unwrap();
                let decrypted = alice_session.decrypt(&encrypted).unwrap();
                assert_eq!(msg.as_bytes(), decrypted.as_slice());
            }
        }
    }

    #[test]
    fn test_session_wrong_spk_id_fails() {
        let (bob_ik, bob_spk, bob_otpk, bundle) = create_test_bundle();

        let (mut alice_session, alice_msg) =
            Session::create_initiator(&bundle, bob_ik.identity_public).unwrap();

        let (identity_key, ephemeral_key, _spk_id, otpk_id) = extract_prekey_data(&alice_msg);

        let result = Session::create_responder(
            &bob_ik,
            &bob_spk,
            Some(&bob_otpk),
            identity_key,
            ephemeral_key,
            999, // Wrong SPK ID
            otpk_id,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_session_decrypt_wrong_message_type() {
        let (bob_ik, bob_spk, bob_otpk, bundle) = create_test_bundle();

        let (mut alice_session, _alice_msg) =
            Session::create_initiator(&bundle, bob_ik.identity_public).unwrap();

        let wrong_message = SessionMessage {
            session_id: alice_session.session_id().to_string(),
            message_type: MessageType::X3DHPreKey {
                identity_key: [0u8; 32],
                ephemeral_key: [0u8; 32],
                spk_id: 1,
                otpk_id: None,
            },
            payload: vec![],
        };

        let result = alice_session.decrypt(&wrong_message);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_empty_message() {
        let (bob_ik, bob_spk, bob_otpk, bundle) = create_test_bundle();

        let (mut alice_session, alice_msg) =
            Session::create_initiator(&bundle, bob_ik.identity_public).unwrap();

        let (identity_key, ephemeral_key, spk_id, otpk_id) = extract_prekey_data(&alice_msg);

        let mut bob_session = Session::create_responder(
            &bob_ik,
            &bob_spk,
            Some(&bob_otpk),
            identity_key,
            ephemeral_key,
            spk_id,
            otpk_id,
        )
        .unwrap();

        let plaintext = b"";
        let encrypted = alice_session.encrypt(plaintext).unwrap();
        let decrypted = bob_session.decrypt(&encrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_session_large_message() {
        let (bob_ik, bob_spk, bob_otpk, bundle) = create_test_bundle();

        let (mut alice_session, alice_msg) =
            Session::create_initiator(&bundle, bob_ik.identity_public).unwrap();

        let (identity_key, ephemeral_key, spk_id, otpk_id) = extract_prekey_data(&alice_msg);

        let mut bob_session = Session::create_responder(
            &bob_ik,
            &bob_spk,
            Some(&bob_otpk),
            identity_key,
            ephemeral_key,
            spk_id,
            otpk_id,
        )
        .unwrap();

        let plaintext = vec![0xABu8; 10000];
        let encrypted = alice_session.encrypt(&plaintext).unwrap();
        let decrypted = bob_session.decrypt(&encrypted).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_session_unique_session_ids() {
        let (bob_ik, bob_spk, bob_otpk, bundle) = create_test_bundle();

        let mut session_ids = std::collections::HashSet::new();

        for _ in 0..20 {
            let (session, _) = Session::create_initiator(&bundle, bob_ik.identity_public).unwrap();
            assert!(session_ids.insert(session.session_id().to_string()));
        }
    }

    #[test]
    fn test_session_state_timestamps() {
        let circle_key = [0x42u8; 32];
        let peer_identity = [0x43u8; 32];

        let session = Session::create_circle_session(circle_key, peer_identity);
        let state = session.state();

        assert!(state.created_at > 0);
        assert!(state.last_used_at > 0);
        assert_eq!(state.created_at, state.last_used_at);
    }

    #[test]
    fn test_session_timestamps_update_on_use() {
        let (bob_ik, bob_spk, bob_otpk, bundle) = create_test_bundle();

        let (mut alice_session, alice_msg) =
            Session::create_initiator(&bundle, bob_ik.identity_public).unwrap();

        let initial_last_used = alice_session.state().last_used_at;
        
        std::thread::sleep(std::time::Duration::from_millis(10));
        
        alice_session.encrypt(b"test").unwrap();
        
        let updated_last_used = alice_session.state().last_used_at;
        assert!(updated_last_used >= initial_last_used);
    }

    #[test]
    fn test_session_process_message() {
        let (bob_ik, bob_spk, bob_otpk, bundle) = create_test_bundle();

        let (mut alice_session, alice_msg) =
            Session::create_initiator(&bundle, bob_ik.identity_public).unwrap();

        let (identity_key, ephemeral_key, spk_id, otpk_id) = extract_prekey_data(&alice_msg);

        let mut bob_session = Session::create_responder(
            &bob_ik,
            &bob_spk,
            Some(&bob_otpk),
            identity_key,
            ephemeral_key,
            spk_id,
            otpk_id,
        )
        .unwrap();

        let plaintext = b"Process message test";
        let encrypted_msg = alice_session.encrypt(plaintext).unwrap();
        
        if let MessageType::RatchetMessage(em) = &encrypted_msg.message_type {
            let decrypted = bob_session.process_message(em).unwrap();
            assert_eq!(plaintext.as_slice(), decrypted.as_slice());
        } else {
            panic!("Expected ratchet message");
        }
    }

    #[test]
    fn test_session_peer_identity() {
        let (bob_ik, bob_spk, bob_otpk, bundle) = create_test_bundle();

        let (alice_session, _) = Session::create_initiator(&bundle, bob_ik.identity_public).unwrap();

        assert_eq!(alice_session.peer_identity(), bob_ik.identity_public);
    }

    #[test]
    fn test_session_from_state_initiator() {
        let (bob_ik, bob_spk, bob_otpk, bundle) = create_test_bundle();

        let (mut alice_session, alice_msg) =
            Session::create_initiator(&bundle, bob_ik.identity_public).unwrap();

        let (identity_key, ephemeral_key, spk_id, otpk_id) = extract_prekey_data(&alice_msg);

        let _bob_session = Session::create_responder(
            &bob_ik,
            &bob_spk,
            Some(&bob_otpk),
            identity_key,
            ephemeral_key,
            spk_id,
            otpk_id,
        )
        .unwrap();

        alice_session.encrypt(b"test1").unwrap();
        alice_session.encrypt(b"test2").unwrap();

        let state = alice_session.state();
        let restored = Session::from_state(state).unwrap();

        assert_eq!(restored.session_id(), alice_session.session_id());
        assert_eq!(restored.role(), SessionRole::Initiator);
        assert_eq!(restored.direction(), SessionDirection::AgentToAgent);
    }

    #[test]
    fn test_session_from_state_responder() {
        let (bob_ik, bob_spk, bob_otpk, bundle) = create_test_bundle();

        let (mut alice_session, alice_msg) =
            Session::create_initiator(&bundle, bob_ik.identity_public).unwrap();

        let (identity_key, ephemeral_key, spk_id, otpk_id) = extract_prekey_data(&alice_msg);

        let mut bob_session = Session::create_responder(
            &bob_ik,
            &bob_spk,
            Some(&bob_otpk),
            identity_key,
            ephemeral_key,
            spk_id,
            otpk_id,
        )
        .unwrap();

        bob_session.encrypt(b"test1").unwrap();

        let state = bob_session.state();
        let restored = Session::from_state(state).unwrap();

        assert_eq!(restored.session_id(), bob_session.session_id());
        assert_eq!(restored.role(), SessionRole::Responder);
    }

    #[test]
    fn test_session_from_state_missing_remote_key_fails() {
        let circle_key = [0x42u8; 32];
        let peer_identity = [0x43u8; 32];

        let session = Session::create_circle_session(circle_key, peer_identity);
        let mut state = session.state();
        state.role = SessionRole::Initiator;
        // Clear ratchet state to simulate missing remote key
        state.ratchet_state.remote_ratchet_key = None;

        let result = Session::from_state(state);
        assert!(result.is_err());
    }

    #[test]
    fn test_serde_message_type() {
        let msg_types = vec![
            MessageType::X3DHPreKey {
                identity_key: [1u8; 32],
                ephemeral_key: [2u8; 32],
                spk_id: 1,
                otpk_id: Some(2),
            },
            MessageType::X3DHResponse,
            MessageType::PreKeyRequest,
        ];

        for mt in msg_types {
            let serialized = serde_json::to_vec(&mt).unwrap();
            let _deserialized: MessageType = serde_json::from_slice(&serialized).unwrap();
        }
    }

    #[test]
    fn test_serde_session_state() {
        let (bob_ik, bob_spk, bob_otpk, bundle) = create_test_bundle();

        let (alice_session, _) = Session::create_initiator(&bundle, bob_ik.identity_public).unwrap();
        let state = alice_session.state();

        let serialized = serde_json::to_vec(&state).unwrap();
        let deserialized: SessionState = serde_json::from_slice(&serialized).unwrap();

        assert_eq!(state.session_id, deserialized.session_id);
        assert_eq!(state.peer_identity, deserialized.peer_identity);
        assert_eq!(state.role, deserialized.role);
        assert_eq!(state.direction, deserialized.direction);
        assert_eq!(state.message_count, deserialized.message_count);
    }

    #[test]
    fn test_session_role_equality() {
        assert_eq!(SessionRole::Initiator, SessionRole::Initiator);
        assert_eq!(SessionRole::Responder, SessionRole::Responder);
        assert_ne!(SessionRole::Initiator, SessionRole::Responder);
    }

    #[test]
    fn test_session_direction_equality() {
        assert_eq!(SessionDirection::AgentToAgent, SessionDirection::AgentToAgent);
        assert_eq!(SessionDirection::CircleEncryption, SessionDirection::CircleEncryption);
        assert_ne!(SessionDirection::AgentToAgent, SessionDirection::CircleEncryption);
    }

    #[test]
    fn test_message_type_clone() {
        let mt = MessageType::X3DHPreKey {
            identity_key: [1u8; 32],
            ephemeral_key: [2u8; 32],
            spk_id: 1,
            otpk_id: Some(2),
        };

        let cloned = mt.clone();
        match (mt, cloned) {
            (MessageType::X3DHPreKey { spk_id: id1, .. }, MessageType::X3DHPreKey { spk_id: id2, .. }) => {
                assert_eq!(id1, id2);
            }
            _ => panic!("Clone failed"),
        }
    }
}
