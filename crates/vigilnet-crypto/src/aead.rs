//! AEAD encryption using AES-256-GCM
//!
//! Provides optimized AES-256-GCM encryption with cipher reuse for high-throughput scenarios.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use std::sync::Mutex;

use crate::{CryptoError, Result};

/// Nonce size in bytes (96 bits for GCM)
pub const NONCE_SIZE: usize = 12;

/// Authentication tag size
pub const TAG_SIZE: usize = 16;

#[cfg(feature = "simd")]
use aes_gcm::aes::Aes256;

/// Thread-local cipher cache for performance
thread_local! {
    static CIPHER_CACHE: Mutex<Option<Aes256Gcm>> = const { Mutex::new(None) };
    static CIPHER_KEY: Mutex<Option<[u8; 32]>> = const { Mutex::new(None) };
}

/// Reusable AES-256-GCM cipher for high-performance encryption
pub struct AesGcmCipher {
    key: [u8; 32],
    #[cfg(feature = "simd")]
    cipher: Aes256Gcm,
}

impl AesGcmCipher {
    /// Create a new cipher with the given key
    pub fn new(key: [u8; 32]) -> Result<Self> {
        #[cfg(feature = "simd")]
        {
            let cipher = Aes256Gcm::new_from_slice(&key)
                .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
            Ok(Self { key, cipher })
        }
        #[cfg(not(feature = "simd"))]
        Ok(Self { key })
    }

    /// Encrypt data using this cipher (nonce is prepended to output)
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "simd")]
        {
            self.encrypt_impl(plaintext)
        }
        #[cfg(not(feature = "simd"))]
        {
            let cipher = Aes256Gcm::new_from_slice(&self.key)
                .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
            self.encrypt_with_cipher(&cipher, plaintext)
        }
    }

    #[cfg(feature = "simd")]
    fn encrypt_impl(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    #[cfg(not(feature = "simd"))]
    fn encrypt_with_cipher(&self, cipher: &Aes256Gcm, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt data using this cipher
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < NONCE_SIZE + TAG_SIZE {
            return Err(CryptoError::DecryptionFailed("Data too short".to_string()));
        }

        #[cfg(feature = "simd")]
        {
            self.decrypt_impl(data)
        }
        #[cfg(not(feature = "simd"))]
        {
            let cipher = Aes256Gcm::new_from_slice(&self.key)
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
            self.decrypt_with_cipher(&cipher, data)
        }
    }

    #[cfg(feature = "simd")]
    fn decrypt_impl(&self, data: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(&data[..NONCE_SIZE]);
        let ciphertext = &data[NONCE_SIZE..];

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }

    #[cfg(not(feature = "simd"))]
    fn decrypt_with_cipher(&self, cipher: &Aes256Gcm, data: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(&data[..NONCE_SIZE]);
        let ciphertext = &data[NONCE_SIZE..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }

    /// Encrypt with additional authenticated data (AAD)
    pub fn encrypt_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::aead::Payload;

        #[cfg(feature = "simd")]
        {
            let mut nonce_bytes = [0u8; NONCE_SIZE];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            let payload = Payload { msg: plaintext, aad };

            let ciphertext = self
                .cipher
                .encrypt(nonce, payload)
                .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

            let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
            result.extend_from_slice(&nonce_bytes);
            result.extend_from_slice(&ciphertext);
            Ok(result)
        }
        #[cfg(not(feature = "simd"))]
        {
            let cipher = Aes256Gcm::new_from_slice(&self.key)
                .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
            
            let mut nonce_bytes = [0u8; NONCE_SIZE];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            let payload = Payload { msg: plaintext, aad };

            let ciphertext = cipher
                .encrypt(nonce, payload)
                .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

            let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
            result.extend_from_slice(&nonce_bytes);
            result.extend_from_slice(&ciphertext);
            Ok(result)
        }
    }

    /// Decrypt with additional authenticated data (AAD)
    pub fn decrypt_with_aad(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::aead::Payload;

        if data.len() < NONCE_SIZE + TAG_SIZE {
            return Err(CryptoError::DecryptionFailed("Data too short".to_string()));
        }

        #[cfg(feature = "simd")]
        {
            let nonce = Nonce::from_slice(&data[..NONCE_SIZE]);
            let ciphertext = &data[NONCE_SIZE..];

            let payload = Payload { msg: ciphertext, aad };

            self.cipher
                .decrypt(nonce, payload)
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
        }
        #[cfg(not(feature = "simd"))]
        {
            let cipher = Aes256Gcm::new_from_slice(&self.key)
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
            
            let nonce = Nonce::from_slice(&data[..NONCE_SIZE]);
            let ciphertext = &data[NONCE_SIZE..];

            let payload = Payload { msg: ciphertext, aad };

            cipher
                .decrypt(nonce, payload)
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
        }
    }
}

/// Get a cached cipher for the given key (thread-local optimization)
pub fn get_cached_cipher(key: &[u8; 32]) -> AesGcmCipher {
    CIPHER_CACHE.with(|cache| {
        let mut cache_guard = cache.lock().unwrap();
        let mut key_guard = CIPHER_KEY.lock().unwrap();
        
        if cache_guard.is_none() || key_guard.as_ref() != Some(key) {
            *cache_guard = Some(Aes256Gcm::new_from_slice(key).expect("Valid key"));
            *key_guard = Some(*key);
        }
        
        drop(cache_guard);
        drop(key_guard);
    });

    AesGcmCipher::new(*key).expect("Valid cipher")
}

/// Encrypt data using AES-256-GCM
///
/// Returns: nonce || ciphertext || tag
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = get_cached_cipher(key);
    cipher.encrypt(plaintext)
}

/// Decrypt data using AES-256-GCM
///
/// Input: nonce || ciphertext || tag
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    let cipher = get_cached_cipher(key);
    cipher.decrypt(data)
}

/// Encrypt with additional authenticated data (AAD)
pub fn encrypt_with_aad(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = get_cached_cipher(key);
    cipher.encrypt_with_aad(plaintext, aad)
}

/// Decrypt with additional authenticated data (AAD)
pub fn decrypt_with_aad(key: &[u8; 32], data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = get_cached_cipher(key);
    cipher.decrypt_with_aad(data, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, VigilNet!";

        let ciphertext = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_with_aad() {
        let key = [0x42u8; 32];
        let plaintext = b"Secret message";
        let aad = b"circuit_id:12345";

        let ciphertext = encrypt_with_aad(&key, plaintext, aad).unwrap();
        let decrypted = decrypt_with_aad(&key, &ciphertext, aad).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let plaintext = b"Secret";

        let ciphertext = encrypt(&key1, plaintext).unwrap();
        assert!(decrypt(&key2, &ciphertext).is_err());
    }

    #[test]
    fn test_aes_gcm_cipher_encrypt_decrypt() {
        let key = [0x42u8; 32];
        let cipher = AesGcmCipher::new(key).unwrap();
        
        let plaintext = b"Test message";
        let ciphertext = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_aes_gcm_cipher_with_aad() {
        let key = [0x42u8; 32];
        let cipher = AesGcmCipher::new(key).unwrap();
        
        let plaintext = b"Secret message";
        let aad = b"additional data";
        
        let ciphertext = cipher.encrypt_with_aad(plaintext, aad).unwrap();
        let decrypted = cipher.decrypt_with_aad(&ciphertext, aad).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_aes_gcm_cipher_with_wrong_aad_fails() {
        let key = [0x42u8; 32];
        let cipher = AesGcmCipher::new(key).unwrap();
        
        let plaintext = b"Secret message";
        let aad = b"correct aad";
        let wrong_aad = b"wrong aad";
        
        let ciphertext = cipher.encrypt_with_aad(plaintext, aad).unwrap();
        let result = cipher.decrypt_with_aad(&ciphertext, wrong_aad);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0x42u8; 32];
        let plaintext = b"";
        
        let ciphertext = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_large_plaintext() {
        let key = [0x42u8; 32];
        let plaintext = vec![0x42u8; 1024 * 1024]; // 1MB
        
        let ciphertext = encrypt(&key, &plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_truncated_ciphertext_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"Test message";
        
        let ciphertext = encrypt(&key, plaintext).unwrap();
        let truncated = &ciphertext[..ciphertext.len() - 5];
        
        let result = decrypt(&key, truncated);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_with_aad_fails() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let plaintext = b"Secret";
        let aad = b"aad";
        
        let cipher1 = AesGcmCipher::new(key1).unwrap();
        let ciphertext = cipher1.encrypt_with_aad(plaintext, aad).unwrap();
        
        let cipher2 = AesGcmCipher::new(key2).unwrap();
        let result = cipher2.decrypt_with_aad(&ciphertext, aad);
        
        assert!(result.is_err());
    }
}
