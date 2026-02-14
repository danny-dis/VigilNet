//! Key management for VigilNet
//!
//! Handles identity keys (Ed25519) and session keys (X25519).

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
pub use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

/// Node identity based on Ed25519 keypair
#[derive(Clone)]
pub struct Identity {
    /// Signing key (private)
    signing_key: SigningKey,
}

impl Identity {
    /// Generate a new random identity
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Get the public verifying key
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the public key bytes (for peer ID)
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> ed25519_dalek::Signature {
        use ed25519_dalek::Signer;
        self.signing_key.sign(message)
    }

    /// Export private key bytes (for storage)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Import from private key bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> crate::Result<Self> {
        let signing_key = SigningKey::from_bytes(bytes);
        Ok(Self { signing_key })
    }
}

/// Session key for circuit encryption (X25519)
#[derive(Clone)]
pub struct SessionKey {
    /// Shared secret derived from DH
    shared_secret: [u8; 32],
}

impl SessionKey {
    /// Create from a shared secret
    pub fn from_shared_secret(secret: [u8; 32]) -> Self {
        Self {
            shared_secret: secret,
        }
    }

    /// Get the key bytes for encryption
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.shared_secret
    }

    /// Perform X25519 key exchange
    pub fn exchange(our_secret: &StaticSecret, their_public: &PublicKey) -> Self {
        let shared = our_secret.diffie_hellman(their_public);
        Self {
            shared_secret: *shared.as_bytes(),
        }
    }

    /// Generate an ephemeral keypair for key exchange
    pub fn generate_ephemeral() -> (EphemeralSecret, PublicKey) {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        (secret, public)
    }

    /// Generate a static keypair for key exchange
    pub fn generate_static() -> (StaticSecret, PublicKey) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        (secret, public)
    }
}

/// Serializable public key info for peer exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyInfo {
    /// Ed25519 identity public key
    pub identity: [u8; 32],
    /// X25519 ephemeral public key (for this session)
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
}
