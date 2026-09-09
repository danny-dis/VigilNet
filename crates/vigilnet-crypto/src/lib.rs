//! VigilNet Cryptography
//!
//! Provides cryptographic primitives for the VigilNet privacy network:
//! - Identity keys (Ed25519)
//! - Session keys (X25519 Diffie-Hellman)
//! - Onion encryption/decryption (AES-GCM layers)
//! - Signal Protocol E2EE (X3DH + Double Ratchet)
//! - Hash functions (BLAKE3)

pub mod aead;
pub mod e2ee;
pub mod hash;
pub mod keys;
pub mod onion;
pub mod ratchet;
pub mod session;
pub mod x3dh;

pub use aead::{decrypt, decrypt_with_aed, encrypt, encrypt_with_aed, AesGcmCipher, NONCE_SIZE, TAG_SIZE};
pub use e2ee::{DoubleRatchet, E2eeMessage};
pub use hash::{blake3, blake3_hex, sha256, sha256_hex};
pub use keys::{Identity, PublicKeyInfo, SessionKey};
pub use onion::{OnionLayer, OnionPacket, CircuitCell, RelayCell, CreateCell, BeginCell, ExtendedCell, ConnectedCell, RelayCommand};
pub use ratchet::{
    DoubleRatchet as Ratchet, EncryptedMessage, MessageHeader, MessageKey, RatchetDH, RatchetKeyPair,
    RatchetState, RatchetSymmetricKey, SkippedMessageKey,
};
pub use session::{
    MessageType, Session, SessionDirection, SessionMessage, SessionRole, SessionState,
};
pub use x3dh::{
    IdentityKeyPair, OneTimePreKey, PreKeyBundle, SignedPreKey, X3DH, X3DHInitiatorState,
};

pub type Result<T> = std::result::Result<T, CryptoError>;

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
