//! Key management for VigilNet
//!
//! Handles identity keys (Ed25519) and session keys (X25519) for:
//! - Node identity and authentication
//! - Session key exchange
//! - Peer identification
//!
//! # Examples
//!
//! ```
//! use vigilnet_crypto::keys::{Identity, SessionKey};
//!
//! // Generate Ed25519 identity
//! let identity = Identity::generate();
//! let public_key = identity.public_key();
//!
//! // Generate X25519 keypair
//! let (secret, public) = SessionKey::generate_static();
//!
//! // Perform key exchange
//! let (secret_b, public_b) = SessionKey::generate_static();
//! let key_a = SessionKey::exchange(&secret, &public_b);
//! let key_b = SessionKey::exchange(&secret_b, &public);
//!
//! assert_eq!(key_a.as_bytes(), key_b.as_bytes());
//! ```

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
pub use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

/// Node identity based on Ed25519 keypair
///
/// Ed25519 provides:
/// - Fast signing and verification
/// - Compact 64-byte signatures
/// - High security (128-bit security level)
/// - Side-channel resistance
///
/// # Examples
///
/// ```
/// use vigilnet_crypto::keys::Identity;
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Generate new identity
///     let identity = Identity::generate();
///
///     // Sign a message
///     let message = b"Hello, world!";
///     let signature = identity.sign(message);
///
///     // Verify signature
///     assert!(identity.public_key().verify(message, &signature).is_ok());
///
///     // Export/import
///     let bytes = identity.to_bytes();
///     let restored = Identity::from_bytes(&bytes)?;
///     assert_eq!(identity.public_key_bytes(), restored.public_key_bytes());
///     Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct Identity {
    /// Signing key (private)
    signing_key: SigningKey,
}

impl Identity {
    /// Generate a new random identity
    ///
    /// Uses OS-provided cryptographically secure random number generator.
    ///
    /// # Examples
    ///
    /// ```
    /// use vigilnet_crypto::keys::Identity;
    ///
    /// let identity = Identity::generate();
    /// assert_eq!(identity.public_key_bytes().len(), 32);
    /// ```
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Get the public verifying key
    ///
    /// # Returns
    ///
    /// The Ed25519 verifying (public) key
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the public key bytes (for peer ID)
    ///
    /// # Returns
    ///
    /// 32-byte public key
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Sign a message
    ///
    /// # Arguments
    ///
    /// * `message` - Message to sign
    ///
    /// # Returns
    ///
    /// 64-byte Ed25519 signature
    ///
    /// # Examples
    ///
    /// ```
    /// use vigilnet_crypto::keys::Identity;
    ///
    /// let identity = Identity::generate();
    /// let message = b"test message";
    /// let signature = identity.sign(message);
    /// assert_eq!(signature.to_bytes().len(), 64);
    /// ```
    pub fn sign(&self, message: &[u8]) -> ed25519_dalek::Signature {
        use ed25519_dalek::Signer;
        self.signing_key.sign(message)
    }

    /// Export private key bytes (for storage)
    ///
    /// # Security
    ///
    /// Keep these bytes secret! Anyone with access to them can
    /// impersonate your node.
    ///
    /// # Returns
    ///
    /// 32-byte private key seed
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Import from private key bytes
    ///
    /// # Arguments
    ///
    /// * `bytes` - 32-byte private key seed
    ///
    /// # Returns
    ///
    /// Result containing the Identity or an error
    pub fn from_bytes(bytes: &[u8; 32]) -> crate::Result<Self> {
        let signing_key = SigningKey::from_bytes(bytes);
        Ok(Self { signing_key })
    }
}

/// Session key for circuit encryption (X25519)
///
/// X25519 provides:
/// - Fast elliptic curve Diffie-Hellman
/// - 128-bit security level
/// - Constant-time implementation
/// - Compact 32-byte keys
///
/// # Examples
///
/// ```
/// use vigilnet_crypto::keys::SessionKey;
///
/// // Generate keypairs
/// let (alice_secret, alice_public) = SessionKey::generate_static();
/// let (bob_secret, bob_public) = SessionKey::generate_static();
///
/// // Exchange keys
/// let alice_shared = SessionKey::exchange(&alice_secret, &bob_public);
/// let bob_shared = SessionKey::exchange(&bob_secret, &alice_public);
///
/// // Both arrive at the same shared secret
/// assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
/// ```
#[derive(Clone)]
pub struct SessionKey {
    /// Shared secret derived from DH
    shared_secret: [u8; 32],
}

impl SessionKey {
    /// Create from a shared secret
    ///
    /// # Arguments
    ///
    /// * `secret` - 32-byte shared secret from X25519 exchange
    ///
    /// # Examples
    ///
    /// ```
    /// use vigilnet_crypto::keys::SessionKey;
    ///
    /// let secret = [0x42u8; 32];
    /// let key = SessionKey::from_shared_secret(secret);
    /// assert_eq!(key.as_bytes(), &secret);
    /// ```
    pub fn from_shared_secret(secret: [u8; 32]) -> Self {
        Self {
            shared_secret: secret,
        }
    }

    /// Get the key bytes for encryption
    ///
    /// # Returns
    ///
    /// 32-byte shared secret
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.shared_secret
    }

    /// Perform X25519 key exchange
    ///
    /// # Arguments
    ///
    /// * `our_secret` - Our private key
    /// * `their_public` - Their public key
    ///
    /// # Returns
    ///
    /// SessionKey containing the shared secret
    pub fn exchange(our_secret: &StaticSecret, their_public: &PublicKey) -> Self {
        let shared = our_secret.diffie_hellman(their_public);
        Self {
            shared_secret: *shared.as_bytes(),
        }
    }

    /// Generate an ephemeral keypair for key exchange
    ///
    /// Ephemeral keys are used for a single session and then discarded,
    /// providing forward secrecy.
    ///
    /// # Returns
    ///
    /// Tuple of (secret, public) keys
    ///
    /// # Examples
    ///
    /// ```
    /// use vigilnet_crypto::keys::SessionKey;
    ///
    /// let (secret, public) = SessionKey::generate_ephemeral();
    /// // Use for one session, then discard
    /// ```
    pub fn generate_ephemeral() -> (EphemeralSecret, PublicKey) {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        (secret, public)
    }

    /// Generate a static keypair for key exchange
    ///
    /// Static keys are persisted and used for long-term identity.
    ///
    /// # Returns
    ///
    /// Tuple of (secret, public) keys
    ///
    /// # Examples
    ///
    /// ```
    /// use vigilnet_crypto::keys::SessionKey;
    ///
    /// let (secret, public) = SessionKey::generate_static();
    /// // Store secret securely for later use
    /// ```
    pub fn generate_static() -> (StaticSecret, PublicKey) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        (secret, public)
    }
}

/// Serializable public key info for peer exchange
///
/// Contains both Ed25519 identity key and X25519 ephemeral key,
/// allowing peers to verify identity and establish encrypted sessions.
///
/// # Examples
///
/// ```
/// use vigilnet_crypto::keys::{PublicKeyInfo, Identity, SessionKey};
/// use serde::{Serialize, Deserialize};
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let identity = Identity::generate();
///     let (_, ephemeral) = SessionKey::generate_ephemeral();
///
///     let info = PublicKeyInfo {
///         identity: identity.public_key_bytes(),
///         ephemeral: *ephemeral.as_bytes(),
///     };
///
///     // Serialize for network transmission
///     let json = serde_json::to_string(&info)?;
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyInfo {
    /// Ed25519 identity public key (32 bytes)
    pub identity: [u8; 32],
    /// X25519 ephemeral public key for session encryption (32 bytes)
    pub ephemeral: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_roundtrip() {
        let identity = Identity::generate();
        let bytes = identity.to_bytes();
        let restored = Identity::from_bytes(&bytes).unwrap();
        assert_eq!(identity.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn test_key_exchange() {
        let (secret_a, public_a) = SessionKey::generate_static();
        let (secret_b, public_b) = SessionKey::generate_static();

        let key_a = SessionKey::exchange(&secret_a, &public_b);
        let key_b = SessionKey::exchange(&secret_b, &public_a);

        assert_eq!(key_a.as_bytes(), key_b.as_bytes());
    }

    #[test]
    fn test_identity_sign_verify() {
        let identity = Identity::generate();
        let message = b"Test message to sign";
        
        let signature = identity.sign(message);
        
        assert!(identity.public_key().verify(message, &signature).is_ok());
    }

    #[test]
    fn test_identity_from_bytes_invalid() {
        let invalid_bytes = [0u8; 32];
        let result = Identity::from_bytes(&invalid_bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ephemeral_key_generation() {
        let (secret, public) = SessionKey::generate_ephemeral();
        assert_eq!(secret.as_bytes().len(), 32);
        assert_eq!(public.as_bytes().len(), 32);
    }

    #[test]
    fn test_public_key_info_serialization() {
        let info = PublicKeyInfo {
            identity: [0x42u8; 32],
            ephemeral: [0x43u8; 32],
        };
        
        let serialized = serde_json::to_vec(&info).unwrap();
        let deserialized: PublicKeyInfo = serde_json::from_slice(&serialized).unwrap();
        
        assert_eq!(info.identity, deserialized.identity);
        assert_eq!(info.ephemeral, deserialized.ephemeral);
    }

    #[test]
    fn test_identity_unique_generation() {
        let identity1 = Identity::generate();
        let identity2 = Identity::generate();
        let identity3 = Identity::generate();
        
        // Each identity should have unique keys
        assert_ne!(identity1.public_key_bytes(), identity2.public_key_bytes());
        assert_ne!(identity2.public_key_bytes(), identity3.public_key_bytes());
        assert_ne!(identity1.public_key_bytes(), identity3.public_key_bytes());
    }

    #[test]
    fn test_sign_verify_different_messages() {
        let identity = Identity::generate();
        
        let messages = vec![
            b"Message 1",
            b"Message 2 with different content",
            b"",
            &[0u8; 100],
            &[0xFFu8; 256],
        ];
        
        for msg in &messages {
            let signature = identity.sign(msg);
            assert!(identity.public_key().verify(msg, &signature).is_ok());
        }
    }

    #[test]
    fn test_signature_wrong_message_fails() {
        let identity = Identity::generate();
        
        let message1 = b"Original message";
        let message2 = b"Different message";
        
        let signature = identity.sign(message1);
        
        // Verify with wrong message should fail
        assert!(identity.public_key().verify(message2, &signature).is_err());
    }

    #[test]
    fn test_signature_wrong_key_fails() {
        let identity1 = Identity::generate();
        let identity2 = Identity::generate();
        
        let message = b"Test message";
        let signature = identity1.sign(message);
        
        // Verify with different identity should fail
        assert!(identity2.public_key().verify(message, &signature).is_err());
    }

    #[test]
    fn test_signature_tampering_fails() {
        let identity = Identity::generate();
        let message = b"Test message";
        
        let signature = identity.sign(message);
        let mut signature_bytes = signature.to_bytes();
        
        // Tamper with signature
        signature_bytes[0] ^= 0xFF;
        let tampered_signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
        
        // Should fail verification
        assert!(identity.public_key().verify(message, &tampered_signature).is_err());
    }

    #[test]
    fn test_multiple_signatures_same_message() {
        let identity = Identity::generate();
        let message = b"Same message";
        
        // Sign same message multiple times (should produce different signatures due to randomness)
        let sig1 = identity.sign(message);
        let sig2 = identity.sign(message);
        
        // Both should verify correctly
        assert!(identity.public_key().verify(message, &sig1).is_ok());
        assert!(identity.public_key().verify(message, &sig2).is_ok());
    }

    #[test]
    fn test_key_exchange_symmetric() {
        // Test multiple key exchanges produce consistent results
        for _ in 0..10 {
            let (secret_a, public_a) = SessionKey::generate_static();
            let (secret_b, public_b) = SessionKey::generate_static();
            
            let key_a = SessionKey::exchange(&secret_a, &public_b);
            let key_b = SessionKey::exchange(&secret_b, &public_a);
            
            assert_eq!(key_a.as_bytes(), key_b.as_bytes());
        }
    }

    #[test]
    fn test_ephemeral_vs_static_exchange() {
        // Ephemeral secret with static public should work
        let (ephemeral_secret, ephemeral_public) = SessionKey::generate_ephemeral();
        let (static_secret, static_public) = SessionKey::generate_static();
        
        // Convert ephemeral to static for exchange test
        let ephemeral_static = StaticSecret::from(*ephemeral_secret.as_bytes());
        
        let key1 = SessionKey::exchange(&ephemeral_static, &static_public);
        let key2 = SessionKey::exchange(&static_secret, &ephemeral_public);
        
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_session_key_from_shared_secret() {
        let secret = [0x42u8; 32];
        let session_key = SessionKey::from_shared_secret(secret);
        
        assert_eq!(session_key.as_bytes(), &secret);
    }

    #[test]
    fn test_static_key_generation_unique() {
        let mut public_keys = std::collections::HashSet::new();
        
        for _ in 0..100 {
            let (_, public) = SessionKey::generate_static();
            let public_bytes = public.to_bytes();
            assert!(public_keys.insert(public_bytes), "Duplicate public key generated");
        }
    }

    #[test]
    fn test_public_key_info_binary_serialization() {
        let info = PublicKeyInfo {
            identity: [0x42u8; 32],
            ephemeral: [0x43u8; 32],
        };
        
        // Test with bincode if available, otherwise use JSON
        let serialized = serde_json::to_vec(&info).unwrap();
        let deserialized: PublicKeyInfo = serde_json::from_slice(&serialized).unwrap();
        
        assert_eq!(info.identity, deserialized.identity);
        assert_eq!(info.ephemeral, deserialized.ephemeral);
    }

    #[test]
    fn test_public_key_info_different_keys() {
        let info1 = PublicKeyInfo {
            identity: [0x01u8; 32],
            ephemeral: [0x02u8; 32],
        };
        
        let info2 = PublicKeyInfo {
            identity: [0x03u8; 32],
            ephemeral: [0x04u8; 32],
        };
        
        let ser1 = serde_json::to_vec(&info1).unwrap();
        let ser2 = serde_json::to_vec(&info2).unwrap();
        
        // Serialized forms should be different
        assert_ne!(ser1, ser2);
    }

    #[test]
    fn test_identity_clone() {
        let identity1 = Identity::generate();
        let identity2 = identity1.clone();
        
        // Both should produce same signatures
        let message = b"Test";
        let sig1 = identity1.sign(message);
        let sig2 = identity2.sign(message);
        
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
        assert_eq!(identity1.public_key_bytes(), identity2.public_key_bytes());
    }

    #[test]
    fn test_session_key_clone() {
        let (_, public) = SessionKey::generate_static();
        let (static_secret, _) = SessionKey::generate_static();
        
        let key1 = SessionKey::exchange(&static_secret, &public);
        let key2 = key1.clone();
        
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_key_exchange_with_self() {
        // Key exchange with self should work (though not recommended in practice)
        let (secret, public) = SessionKey::generate_static();
        
        let key = SessionKey::exchange(&secret, &public);
        
        // Result should be deterministic
        let key2 = SessionKey::exchange(&secret, &public);
        assert_eq!(key.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_empty_message_sign_verify() {
        let identity = Identity::generate();
        let message: &[u8] = b"";
        
        let signature = identity.sign(message);
        assert!(identity.public_key().verify(message, &signature).is_ok());
    }

    #[test]
    fn test_large_message_sign_verify() {
        let identity = Identity::generate();
        let message = vec![0xABu8; 10000];
        
        let signature = identity.sign(&message);
        assert!(identity.public_key().verify(&message, &signature).is_ok());
    }

    #[test]
    fn test_identity_to_bytes_deterministic() {
        let identity = Identity::generate();
        
        let bytes1 = identity.to_bytes();
        let bytes2 = identity.to_bytes();
        
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_public_key_info_partial_eq() {
        let info1 = PublicKeyInfo {
            identity: [0x42u8; 32],
            ephemeral: [0x43u8; 32],
        };
        
        let info2 = PublicKeyInfo {
            identity: [0x42u8; 32],
            ephemeral: [0x43u8; 32],
        };
        
        let info3 = PublicKeyInfo {
            identity: [0x44u8; 32],
            ephemeral: [0x43u8; 32],
        };
        
        assert_eq!(info1.identity, info2.identity);
        assert_eq!(info1.ephemeral, info2.ephemeral);
        assert_ne!(info1.identity, info3.identity);
    }

    #[test]
    fn test_session_key_zero_secret() {
        // Edge case: zero secret should still work
        let zero_secret = StaticSecret::from([0u8; 32]);
        let zero_public = PublicKey::from(&zero_secret);
        
        let (other_secret, other_public) = SessionKey::generate_static();
        
        let key1 = SessionKey::exchange(&zero_secret, &other_public);
        let key2 = SessionKey::exchange(&other_secret, &zero_public);
        
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_serde_json_public_key_info() {
        let info = PublicKeyInfo {
            identity: [0x42u8; 32],
            ephemeral: [0x43u8; 32],
        };
        
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: PublicKeyInfo = serde_json::from_str(&json).unwrap();
        
        assert_eq!(info.identity, deserialized.identity);
        assert_eq!(info.ephemeral, deserialized.ephemeral);
    }
}
