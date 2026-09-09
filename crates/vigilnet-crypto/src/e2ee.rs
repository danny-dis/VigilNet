//! High-level E2EE interface combining X3DH and Double Ratchet

pub mod e2ee {
    use crate::ratchet::{DoubleRatchet as Ratchet, EncryptedMessage, MessageHeader, RatchetState};
    use crate::x3dh::{IdentityKeyPair, OneTimePreKey, PreKeyBundle, SignedPreKey};
    use crate::{CryptoError, Result};
    use serde::{Deserialize, Serialize};

    #[derive(Clone)]
    pub struct DoubleRatchet {
        ratchet: Ratchet,
    }

    #[derive(Serialize, Deserialize)]
    pub struct E2eeMessage {
        pub header: MessageHeader,
        pub ciphertext: Vec<u8>,
    }

    impl DoubleRatchet {
        /// Initialize as Alice (initiator) with a pre-key bundle
        /// 
        /// Note: This is a simplified interface that creates a ratchet from the shared secret
        /// derived from the X3DH key agreement.
        pub fn new_alice(
            identity_key: IdentityKeyPair,
            prekey_bundle: PreKeyBundle,
        ) -> Result<Self> {
            use crate::x3dh::X3DH;
            
            // Perform X3DH key agreement
            let (_, shared_secret, _) = X3DH::initiator_initiate(&prekey_bundle)?;
            
            // Create ratchet as initiator
            let ratchet = Ratchet::initiator(shared_secret, prekey_bundle.signed_prekey.public)?;

            Ok(Self { ratchet })
        }

        /// Initialize as Bob (responder) 
        /// 
        /// Note: Bob needs to wait for Alice's initial message to complete setup
        pub fn new_bob(shared_secret: [u8; 32]) -> Result<Self> {
            let ratchet = Ratchet::responder(shared_secret);

            Ok(Self { ratchet })
        }

        /// Encrypt a message using the Double Ratchet
        pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Result<EncryptedMessage> {
            self.ratchet
                .encrypt(plaintext)
                .map_err(|e| CryptoError::RatchetError(e.to_string()))
        }

        /// Decrypt a message using the Double Ratchet
        pub fn decrypt_message(&mut self, message: &[u8]) -> Result<Vec<u8>> {
            let encrypted = EncryptedMessage::from_bytes(message)
                .map_err(|e| CryptoError::InvalidMessage(e.to_string()))?;

            self.ratchet
                .decrypt(&encrypted.header, &encrypted.ciphertext)
                .map_err(|e| CryptoError::RatchetError(e.to_string()))
        }

        /// Get the ratchet state for persistence
        pub fn state(&self) -> &RatchetState {
            self.ratchet.state()
        }

        /// Get current sending public key
        pub fn sending_public_key(&self) -> [u8; 32] {
            self.ratchet.sending_public_key()
        }

        /// Perform a DH ratchet step
        pub fn dh_ratchet(&mut self, remote_public: &[u8; 32]) -> Result<()> {
            self.ratchet
                .dh_ratchet(remote_public)
                .map_err(|e| CryptoError::RatchetError(e.to_string()))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::x3dh::{IdentityKeyPair, SignedPreKey, OneTimePreKey};

        fn create_test_bundle() -> (IdentityKeyPair, PreKeyBundle) {
            let bob_ik = IdentityKeyPair::generate();
            let bob_spk = SignedPreKey::generate(&bob_ik, 1);
            let bob_otpk = OneTimePreKey::generate(1);

            let bundle = PreKeyBundle {
                identity_key: bob_ik.identity_public,
                signed_prekey: bob_spk,
                one_time_prekey: Some(bob_otpk),
            };

            (bob_ik, bundle)
        }

        #[test]
        fn test_e2ee_message_serialization() {
            let header = MessageHeader {
                public_key: Some([0x42u8; 32]),
                previous_chain_length: 0,
                message_number: 0,
            };

            let msg = E2eeMessage {
                header,
                ciphertext: vec![1, 2, 3, 4, 5],
            };

            let serialized = serde_json::to_vec(&msg).unwrap();
            let deserialized: E2eeMessage = serde_json::from_slice(&serialized).unwrap();

            assert_eq!(msg.ciphertext, deserialized.ciphertext);
        }

        #[test]
        fn test_double_ratchet_new_alice() {
            let (bob_ik, bundle) = create_test_bundle();
            let alice_ik = IdentityKeyPair::generate();

            let result = DoubleRatchet::new_alice(alice_ik, bundle);
            assert!(result.is_ok());

            let alice = result.unwrap();
            assert_eq!(alice.state().root_key.len(), 32);
        }

        #[test]
        fn test_double_ratchet_new_bob() {
            let shared_secret = [0x42u8; 32];

            let result = DoubleRatchet::new_bob(shared_secret);
            assert!(result.is_ok());

            let bob = result.unwrap();
            assert_eq!(bob.state().root_key, shared_secret);
        }

        #[test]
        fn test_encrypt_decrypt_roundtrip() {
            let (bob_ik, bundle) = create_test_bundle();
            let alice_ik = IdentityKeyPair::generate();

            let mut alice = DoubleRatchet::new_alice(alice_ik, bundle).unwrap();
            let shared_secret = alice.state().root_key;
            let mut bob = DoubleRatchet::new_bob(shared_secret).unwrap();

            // Perform initial DH ratchet
            alice.dh_ratchet(&bob.sending_public_key()).unwrap();
            bob.dh_ratchet(&alice.sending_public_key()).unwrap();

            let plaintext = b"Hello, secure world!";
            let encrypted = alice.encrypt_message(plaintext).unwrap();
            
            // Serialize and deserialize
            let serialized = encrypted.to_bytes();
            let decrypted = bob.decrypt_message(&serialized).unwrap();

            assert_eq!(plaintext.as_slice(), decrypted.as_slice());
        }

        #[test]
        fn test_multiple_messages() {
            let (bob_ik, bundle) = create_test_bundle();
            let alice_ik = IdentityKeyPair::generate();

            let mut alice = DoubleRatchet::new_alice(alice_ik, bundle).unwrap();
            let shared_secret = alice.state().root_key;
            let mut bob = DoubleRatchet::new_bob(shared_secret).unwrap();

            // Perform initial DH ratchet
            alice.dh_ratchet(&bob.sending_public_key()).unwrap();
            bob.dh_ratchet(&alice.sending_public_key()).unwrap();

            for i in 0..10 {
                let plaintext = format!("Message {}", i);
                let encrypted = alice.encrypt_message(plaintext.as_bytes()).unwrap();
                let serialized = encrypted.to_bytes();
                let decrypted = bob.decrypt_message(&serialized).unwrap();
                assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
            }
        }

        #[test]
        fn test_bidirectional_communication() {
            let (bob_ik, bundle) = create_test_bundle();
            let alice_ik = IdentityKeyPair::generate();

            let mut alice = DoubleRatchet::new_alice(alice_ik, bundle).unwrap();
            let shared_secret = alice.state().root_key;
            let mut bob = DoubleRatchet::new_bob(shared_secret).unwrap();

            // Initial DH ratchet
            alice.dh_ratchet(&bob.sending_public_key()).unwrap();
            bob.dh_ratchet(&alice.sending_public_key()).unwrap();

            // Alice -> Bob
            let msg1 = b"Alice to Bob";
            let encrypted1 = alice.encrypt_message(msg1).unwrap();
            let decrypted1 = bob.decrypt_message(&encrypted1.to_bytes()).unwrap();
            assert_eq!(msg1.as_slice(), decrypted1.as_slice());

            // Bob -> Alice
            let msg2 = b"Bob to Alice";
            let encrypted2 = bob.encrypt_message(msg2).unwrap();
            let decrypted2 = alice.decrypt_message(&encrypted2.to_bytes()).unwrap();
            assert_eq!(msg2.as_slice(), decrypted2.as_slice());
        }

        #[test]
        fn test_decrypt_invalid_message() {
            let (bob_ik, bundle) = create_test_bundle();
            let alice_ik = IdentityKeyPair::generate();

            let mut alice = DoubleRatchet::new_alice(alice_ik, bundle).unwrap();

            // Try to decrypt invalid data
            let invalid_message = vec![0u8; 10];
            let result = alice.decrypt_message(&invalid_message);
            assert!(result.is_err());
        }

        #[test]
        fn test_decrypt_truncated_message() {
            let (bob_ik, bundle) = create_test_bundle();
            let alice_ik = IdentityKeyPair::generate();

            let mut alice = DoubleRatchet::new_alice(alice_ik, bundle).unwrap();

            // Try to decrypt truncated data
            let truncated = vec![0u8; 5]; // Too short to be valid
            let result = alice.decrypt_message(&truncated);
            assert!(result.is_err());
        }

        #[test]
        fn test_empty_message() {
            let (bob_ik, bundle) = create_test_bundle();
            let alice_ik = IdentityKeyPair::generate();

            let mut alice = DoubleRatchet::new_alice(alice_ik, bundle).unwrap();
            let shared_secret = alice.state().root_key;
            let mut bob = DoubleRatchet::new_bob(shared_secret).unwrap();

            alice.dh_ratchet(&bob.sending_public_key()).unwrap();
            bob.dh_ratchet(&alice.sending_public_key()).unwrap();

            let plaintext = b"";
            let encrypted = alice.encrypt_message(plaintext).unwrap();
            let decrypted = bob.decrypt_message(&encrypted.to_bytes()).unwrap();

            assert_eq!(plaintext.as_slice(), decrypted.as_slice());
        }

        #[test]
        fn test_large_message() {
            let (bob_ik, bundle) = create_test_bundle();
            let alice_ik = IdentityKeyPair::generate();

            let mut alice = DoubleRatchet::new_alice(alice_ik, bundle).unwrap();
            let shared_secret = alice.state().root_key;
            let mut bob = DoubleRatchet::new_bob(shared_secret).unwrap();

            alice.dh_ratchet(&bob.sending_public_key()).unwrap();
            bob.dh_ratchet(&alice.sending_public_key()).unwrap();

            let plaintext = vec![0xABu8; 10000];
            let encrypted = alice.encrypt_message(&plaintext).unwrap();
            let decrypted = bob.decrypt_message(&encrypted.to_bytes()).unwrap();

            assert_eq!(plaintext, decrypted);
        }

        #[test]
        fn test_state_access() {
            let (bob_ik, bundle) = create_test_bundle();
            let alice_ik = IdentityKeyPair::generate();

            let alice = DoubleRatchet::new_alice(alice_ik, bundle).unwrap();
            let state = alice.state();

            // Verify state has expected structure
            assert_eq!(state.root_key.len(), 32);
        }

        #[test]
        fn test_sending_public_key() {
            let (bob_ik, bundle) = create_test_bundle();
            let alice_ik = IdentityKeyPair::generate();

            let alice = DoubleRatchet::new_alice(alice_ik, bundle).unwrap();
            let public_key = alice.sending_public_key();

            assert_eq!(public_key.len(), 32);
        }

        #[test]
        fn test_dh_ratchet_changes_keys() {
            let (bob_ik, bundle) = create_test_bundle();
            let alice_ik = IdentityKeyPair::generate();

            let mut alice = DoubleRatchet::new_alice(alice_ik, bundle).unwrap();
            let shared_secret = alice.state().root_key;
            let bob = DoubleRatchet::new_bob(shared_secret).unwrap();

            let old_key = alice.sending_public_key();
            
            alice.dh_ratchet(&bob.sending_public_key()).unwrap();
            
            let new_key = alice.sending_public_key();
            assert_ne!(old_key, new_key);
        }

        #[test]
        fn test_e2ee_message_clone() {
            let header = MessageHeader {
                public_key: Some([0x42u8; 32]),
                previous_chain_length: 0,
                message_number: 0,
            };

            let msg = E2eeMessage {
                header: header.clone(),
                ciphertext: vec![1, 2, 3],
            };

            let cloned = msg.clone();
            assert_eq!(msg.ciphertext, cloned.ciphertext);
        }

        #[test]
        fn test_double_ratchet_clone() {
            let (bob_ik, bundle) = create_test_bundle();
            let alice_ik = IdentityKeyPair::generate();

            let alice = DoubleRatchet::new_alice(alice_ik, bundle).unwrap();
            let cloned = alice.clone();

            assert_eq!(alice.sending_public_key(), cloned.sending_public_key());
        }

        #[test]
        fn test_new_alice_without_otpk() {
            let bob_ik = IdentityKeyPair::generate();
            let bob_spk = SignedPreKey::generate(&bob_ik, 1);

            let bundle = PreKeyBundle {
                identity_key: bob_ik.identity_public,
                signed_prekey: bob_spk,
                one_time_prekey: None,
            };

            let alice_ik = IdentityKeyPair::generate();
            let result = DoubleRatchet::new_alice(alice_ik, bundle);
            assert!(result.is_ok());
        }
    }
}
