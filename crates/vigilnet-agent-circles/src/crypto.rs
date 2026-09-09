use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[derive(Error, Debug)]
pub enum CircleCryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
    #[error("Invalid key material")]
    InvalidKeyMaterial,
    #[error("Forward secrecy violation: stale key epoch")]
    StaleKeyEpoch,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct KeyEpoch {
    pub epoch: u64,
    pub key: [u8; 32],
    pub nonce: [u8; 12],
}

impl KeyEpoch {
    pub fn new(epoch: u64) -> Self {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut nonce);
        Self { epoch, key, nonce }
    }

    pub fn derive_from_group_key(group_key: &[u8], epoch: u64) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(group_key);
        hasher.update(epoch.to_le_bytes());
        let result = hasher.finalize();

        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        key.copy_from_slice(&result[0..32]);
        nonce.copy_from_slice(&result[32..44]);

        Self { epoch, key, nonce }
    }
}

pub struct CircleCipher {
    current_epoch: KeyEpoch,
    previous_key: Option<KeyEpoch>,
    max_epochs_stored: usize,
}

impl CircleCipher {
    pub fn new(group_key: &[u8], initial_epoch: u64) -> Self {
        let current_epoch = KeyEpoch::derive_from_group_key(group_key, initial_epoch);
        Self {
            current_epoch,
            previous_key: None,
            max_epochs_stored: 2,
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CircleCryptoError> {
        let cipher = Aes256Gcm::new_from_slice(&self.current_epoch.key)
            .map_err(|e| CircleCryptoError::EncryptionFailed(e.to_string()))?;

        let nonce = Nonce::from_slice(&self.current_epoch.nonce);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CircleCryptoError::EncryptionFailed(e.to_string()))?;

        let mut result = Vec::with_capacity(8 + 12 + ciphertext.len());
        result.extend_from_slice(&self.current_epoch.epoch.to_le_bytes());
        result.extend_from_slice(&self.current_epoch.nonce);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CircleCryptoError> {
        if ciphertext.len() < 20 {
            return Err(CircleCryptoError::DecryptionFailed("Ciphertext too short".into()));
        }

        let epoch = u64::from_le_bytes(
            ciphertext[0..8]
                .try_into()
                .map_err(|_| CircleCryptoError::DecryptionFailed("Invalid epoch bytes".into()))?,
        );
        let nonce = &ciphertext[8..20];
        let encrypted = &ciphertext[20..];

        let key = if epoch == self.current_epoch.epoch {
            &self.current_epoch.key
        } else if let Some(ref prev) = self.previous_key {
            if epoch == prev.epoch {
                &prev.key
            } else {
                return Err(CircleCryptoError::StaleKeyEpoch);
            }
        } else {
            return Err(CircleCryptoError::StaleKeyEpoch);
        };

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| CircleCryptoError::DecryptionFailed(e.to_string()))?;

        let nonce = Nonce::from_slice(nonce);
        cipher
            .decrypt(nonce, encrypted)
            .map_err(|e| CircleCryptoError::DecryptionFailed(e.to_string()))
    }

    pub fn rotate_epoch(&mut self, new_group_key: &[u8]) -> KeyEpoch {
        let new_epoch = KeyEpoch::derive_from_group_key(new_group_key, self.current_epoch.epoch + 1);
        self.previous_key = Some(std::mem::replace(&mut self.current_epoch, new_epoch.clone()));
        new_epoch
    }

    pub fn current_epoch_number(&self) -> u64 {
        self.current_epoch.epoch
    }
}

pub fn derive_group_key(member_keys: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"VIGILNET_CIRCLE_KEY_DERIVATION_V1");
    for key in member_keys {
        hasher.update(key);
    }
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

pub fn derive_key_pair_from_seed(seed: &[u8]) -> (StaticSecret, X25519PublicKey) {
    let hash = {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.finalize()
    };
    let secret = StaticSecret::from(hash);
    let public = X25519PublicKey::from(&secret);
    (secret, public)
}

pub fn compute_shared_secret(
    local_secret: &StaticSecret,
    remote_public: &X25519PublicKey,
) -> [u8; 32] {
    let shared = local_secret.diffie_hellman(remote_public);
    let mut result = [0u8; 32];
    result.copy_from_slice(shared.as_bytes());
    result
}

pub fn hash_to_scalar(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"VIGILNET_SCALAR_HASH_V1");
    hasher.update(input);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_key_derivation() {
        let key1 = b"member1_key_32_bytes_long!!!!";
        let key2 = b"member2_key_32_bytes_long!!!!";
        let key3 = b"member3_key_32_bytes_long!!!!";

        let group_key = derive_group_key(&[key1, key2, key3]);
        let group_key2 = derive_group_key(&[key1, key2, key3]);

        assert_eq!(group_key, group_key2);

        let group_key_different = derive_group_key(&[key1, key2]);
        assert_ne!(group_key, group_key_different);
    }

    #[test]
    fn test_circle_cipher() {
        let group_key = derive_group_key(&[b"key1", b"key2"]);
        let cipher = CircleCipher::new(&group_key, 0);

        let plaintext = b"Hello, HIPAA-compliant world!";
        let ciphertext = cipher.encrypt(plaintext).expect("Encryption should succeed");
        let decrypted = cipher.decrypt(&ciphertext).expect("Decryption should succeed");

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_epoch_rotation() {
        let mut cipher = CircleCipher::new(b"initial_group_key_12345678901", 0);

        let p1 = b"period 1";
        let c1 = cipher.encrypt(p1).expect("Encryption should succeed");

        let new_group_key = derive_group_key(&[b"new_key_material"]);
        cipher.rotate_epoch(&new_group_key);

        let p2 = b"period 2";
        let c2 = cipher.encrypt(p2).expect("Encryption should succeed");

        assert!(cipher.decrypt(&c2).is_ok());
        assert!(cipher.decrypt(&c1).is_ok());
    }
}
