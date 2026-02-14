//! VigilNet Cryptography
//!
//! Provides cryptographic primitives for the VigilNet privacy network:
//! - Identity keys (Ed25519)
//! - Session keys (X25519 Diffie-Hellman)
//! - Onion encryption/decryption (AES-GCM layers)
//! - Signal Protocol E2EE (X3DH + Double Ratchet)

pub mod aead;
pub mod keys;
pub mod onion;
pub mod ratchet;
pub mod session;
pub mod x3dh;

pub use aead::{decrypt, encrypt, decrypt_with_aad, encrypt_with_aad, AesGcmCipher, NONCE_SIZE, TAG_SIZE};
pub use keys::{Identity, PublicKeyInfo, SessionKey};
pub use onion::{OnionLayer, OnionPacket, CircuitCell, RelayCell, CreateCell, BeginCell, ExtendedCell, ConnectedCell, RelayCommand};
pub use ratchet::{
    DoubleRatchet, EncryptedMessage, MessageHeader, MessageKey, RatchetDH, RatchetKeyPair,
    RatchetState, RatchetSymmetricKey, SkippedMessageKey,
};
pub use session::{
    MessageType, Session, SessionDirection, SessionMessage, SessionRole, SessionState,
};
pub use x3dh::{
    IdentityKeyPair, OneTimePreKey, PreKeyBundle, SignedPreKey, X3DH, X3DHInitiatorState,
};

/// Result type for crypto operations
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Crypto error types
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Key generation failed: {0}")]
    KeyGenFailed(String),

    #[error("X3DH key agreement failed: {0}")]
    X3DHFailed(String),

    #[error("Ratchet error: {0}")]
    RatchetError(String),

    #[error("Session error: {0}")]
    SessionError(String),

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Skipped message: {0}")]
    SkippedMessage(u32),
}
