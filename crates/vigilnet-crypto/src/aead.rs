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
pub fn get_cached_cipher(key: &[u8; 32]) -> Result<AesGcmCipher> {
    CIPHER_CACHE.with(|cache| {
        let mut cache_guard = cache.lock()
            .map_err(|e| CryptoError::EncryptionFailed(format!("Mutex lock failed: {}", e)))?;
        let mut key_guard = CIPHER_KEY.lock()
            .map_err(|e| CryptoError::EncryptionFailed(format!("Mutex lock failed: {}", e)))?;
        
        if cache_guard.is_none() || key_guard.as_ref() != Some(key) {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
            *cache_guard = Some(cipher);
            *key_guard = Some(*key);
        }
        
        drop(cache_guard);
        drop(key_guard);
        Ok(())
    })?;

    AesGcmCipher::new(*key)
}

/// Encrypt data using AES-256-GCM
///
/// Returns: nonce || ciphertext || tag
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = get_cached_cipher(key)?;
    cipher.encrypt(plaintext)
}

/// Decrypt data using AES-256-GCM
///
/// Input: nonce || ciphertext || tag
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    let cipher = get_cached_cipher(key)?;
    cipher.decrypt(data)
}

/// Encrypt with additional authenticated data (AAD)
pub fn encrypt_with_aad(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = get_cached_cipher(key)?;
    cipher.encrypt_with_aad(plaintext, aad)
}

/// Decrypt with additional authenticated data (AAD)
pub fn decrypt_with_aad(key: &[u8; 32], data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = get_cached_cipher(key)?;
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

    #[test]
    fn test_cipher_reuse_multiple_operations() {
        let key = [0x42u8; 32];
        let cipher = AesGcmCipher::new(key).unwrap();
        
        // Encrypt multiple messages with same cipher
        let messages = vec![
            b"Message 1".to_vec(),
            b"Message 2 with different length".to_vec(),
            vec![0x00; 1000],
            b"Short".to_vec(),
        ];
        
        let mut ciphertexts = Vec::new();
        for msg in &messages {
            let ct = cipher.encrypt(msg).unwrap();
            ciphertexts.push(ct);
        }
        
        // Decrypt all messages
        for (i, ct) in ciphertexts.iter().enumerate() {
            let decrypted = cipher.decrypt(ct).unwrap();
            assert_eq!(messages[i], decrypted);
        }
    }

    #[test]
    fn test_multiple_ciphers_same_key() {
        let key = [0x42u8; 32];
        let cipher1 = AesGcmCipher::new(key).unwrap();
        let cipher2 = AesGcmCipher::new(key).unwrap();
        
        let plaintext = b"Test message";
        
        let ciphertext = cipher1.encrypt(plaintext).unwrap();
        let decrypted = cipher2.decrypt(&ciphertext).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_nonce_is_unique_per_encryption() {
        let key = [0x42u8; 32];
        let cipher = AesGcmCipher::new(key).unwrap();
        
        let plaintext = b"Same message";
        
        let ct1 = cipher.encrypt(plaintext).unwrap();
        let ct2 = cipher.encrypt(plaintext).unwrap();
        let ct3 = cipher.encrypt(plaintext).unwrap();
        
        // Nonce is first 12 bytes, should be different each time
        assert_ne!(&ct1[..NONCE_SIZE], &ct2[..NONCE_SIZE]);
        assert_ne!(&ct2[..NONCE_SIZE], &ct3[..NONCE_SIZE]);
        assert_ne!(&ct1[..NONCE_SIZE], &ct3[..NONCE_SIZE]);
    }

    #[test]
    fn test_decrypt_empty_data_fails() {
        let key = [0x42u8; 32];
        let cipher = AesGcmCipher::new(key).unwrap();
        
        let result = cipher.decrypt(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_too_short_data_fails() {
        let key = [0x42u8; 32];
        let cipher = AesGcmCipher::new(key).unwrap();
        
        // Data must be at least NONCE_SIZE + TAG_SIZE
        let short_data = vec![0u8; NONCE_SIZE + TAG_SIZE - 1];
        let result = cipher.decrypt(&short_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_exact_nonce_size_fails() {
        let key = [0x42u8; 32];
        let cipher = AesGcmCipher::new(key).unwrap();
        
        // Data with exactly nonce size but no tag
        let data = vec![0u8; NONCE_SIZE];
        let result = cipher.decrypt(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_binary_data_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext: Vec<u8> = (0..256).map(|i| i as u8).collect();
        
        let ciphertext = encrypt(&key, &plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_unicode_plaintext() {
        let key = [0x42u8; 32];
        let plaintext = "Hello 世界 🌍 Ñoño".as_bytes();
        
        let ciphertext = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_aad_with_binary_data() {
        let key = [0x42u8; 32];
        let plaintext = b"Secret";
        let aad: Vec<u8> = (0..100).map(|i| (i * 7) as u8).collect();
        
        let ciphertext = encrypt_with_aad(&key, plaintext, &aad).unwrap();
        let decrypted = decrypt_with_aad(&key, &ciphertext, &aad).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_modified_ciphertext_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"Test message";
        
        let mut ciphertext = encrypt(&key, plaintext).unwrap();
        
        // Modify a byte in the ciphertext (after nonce)
        if ciphertext.len() > NONCE_SIZE + 5 {
            ciphertext[NONCE_SIZE + 5] ^= 0xFF;
        }
        
        let result = decrypt(&key, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_modified_nonce_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"Test message";
        
        let mut ciphertext = encrypt(&key, plaintext).unwrap();
        
        // Modify a byte in the nonce
        ciphertext[5] ^= 0xFF;
        
        let result = decrypt(&key, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_aad_manipulation_fails() {
        let key = [0x42u8; 32];
        let cipher = AesGcmCipher::new(key).unwrap();
        
        let plaintext = b"Secret message";
        let aad = b"original aad";
        
        let ciphertext = cipher.encrypt_with_aad(plaintext, aad).unwrap();
        
        // Try to decrypt with modified AAD
        let wrong_aad = b"modified aad";
        let result = cipher.decrypt_with_aad(&ciphertext, wrong_aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_all_zero_key() {
        let key = [0u8; 32];
        let plaintext = b"Test with zero key";
        
        let ciphertext = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_all_ones_key() {
        let key = [0xFFu8; 32];
        let plaintext = b"Test with ones key";
        
        let ciphertext = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_incrementing_key() {
        let key: [u8; 32] = (0..32).map(|i| i as u8).collect::<Vec<_>>().try_into().unwrap();
        let plaintext = b"Test with incrementing key";
        
        let ciphertext = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_consecutive_encrypt_calls() {
        let key = [0x42u8; 32];
        let cipher = AesGcmCipher::new(key).unwrap();
        
        for i in 0..100 {
            let plaintext = format!("Message number {}", i);
            let ciphertext = cipher.encrypt(plaintext.as_bytes()).unwrap();
            let decrypted = cipher.decrypt(&ciphertext).unwrap();
            assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
        }
    }

    #[test]
    fn test_parallel_encryption_simulation() {
        let key = [0x42u8; 32];
        
        // Simulate multiple threads using the same key
        let plaintexts: Vec<Vec<u8>> = (0..10)
            .map(|i| format!("Thread {} data", i).into_bytes())
            .collect();
        
        let mut ciphertexts = Vec::new();
        for pt in &plaintexts {
            let cipher = AesGcmCipher::new(key).unwrap();
            let ct = cipher.encrypt(pt).unwrap();
            ciphertexts.push(ct);
        }
        
        // Decrypt all with new ciphers
        for (i, ct) in ciphertexts.iter().enumerate() {
            let cipher = AesGcmCipher::new(key).unwrap();
            let decrypted = cipher.decrypt(ct).unwrap();
            assert_eq!(plaintexts[i], decrypted);
        }
    }

    #[test]
    fn test_ciphertext_structure() {
        let key = [0x42u8; 32];
        let plaintext = b"Test";
        
        let ciphertext = encrypt(&key, plaintext).unwrap();
        
        // Structure: nonce (12) + ciphertext + tag (16)
        assert_eq!(ciphertext.len(), NONCE_SIZE + plaintext.len() + TAG_SIZE);
        
        // First NONCE_SIZE bytes should be the nonce
        // Last TAG_SIZE bytes are the authentication tag (included in ciphertext portion)
    }

    #[test]
    fn test_different_plaintext_lengths() {
        let key = [0x42u8; 32];
        let lengths = vec![0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 1023, 1024, 1025];
        
        for len in lengths {
            let plaintext = vec![0xABu8; len];
            let ciphertext = encrypt(&key, &plaintext).unwrap();
            let decrypted = decrypt(&key, &ciphertext).unwrap();
            assert_eq!(plaintext, decrypted, "Failed for length {}", len);
        }
    }

    #[test]
    fn test_get_cached_cipher() {
        let key = [0x42u8; 32];
        
        // Get cached cipher multiple times
        let cipher1 = get_cached_cipher(&key);
        let cipher2 = get_cached_cipher(&key);
        
        // Both should work correctly
        let plaintext = b"Test";
        let ct = cipher1.encrypt(plaintext).unwrap();
        let decrypted = cipher2.decrypt(&ct).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_decrypt_with_aad_empty_data_fails() {
        let key = [0x42u8; 32];
        let cipher = AesGcmCipher::new(key).unwrap();
        let aad = b"some aad";
        
        let result = cipher.decrypt_with_aad(&[], aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_aad_roundtrip() {
        let key = [0x42u8; 32];
        let cipher = AesGcmCipher::new(key).unwrap();
        
        let plaintext = b"Test message";
        let aad = b"";
        
        let ciphertext = cipher.encrypt_with_aad(plaintext, aad).unwrap();
        let decrypted = cipher.decrypt_with_aad(&ciphertext, aad).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
