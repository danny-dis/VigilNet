//! Hash functions module
//!
//! Provides cryptographic hash functions for VigilNet:
//! - BLAKE3: Fast, modern cryptographic hash function
//! - SHA-256: Industry-standard hash for compatibility
//!
//! # Examples
//!
//! ```
//! use vigilnet_crypto::{blake3, blake3_hex, sha256, sha256_hex};
//!
//! let data = b"Hello, world!";
//!
//! // BLAKE3 hashing
//! let hash = blake3(data);
//! let hash_hex = blake3_hex(data);
//!
//! // SHA-256 hashing
//! let hash = sha256(data);
//! let hash_hex = sha256_hex(data);
//! ```

use blake3::Hasher;
use sha2::{Sha256, Digest};

/// Compute BLAKE3 hash of data
///
/// BLAKE3 is a fast, modern cryptographic hash function that is:
/// - Faster than MD5 and SHA-1
/// - As secure as SHA-3
/// - Highly parallelizable
///
/// # Arguments
///
/// * `data` - Input data to hash
///
/// # Returns
///
/// 32-byte hash as Vec<u8>
///
/// # Examples
///
/// ```
/// use vigilnet_crypto::hash::blake3;
///
/// let data = b"test data";
/// let hash = blake3(data);
/// assert_eq!(hash.len(), 32);
/// ```
pub fn blake3(data: &[u8]) -> Vec<u8> {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize().as_bytes().to_vec()
}

/// Compute BLAKE3 hash and return as hex string
///
/// # Arguments
///
/// * `data` - Input data to hash
///
/// # Returns
///
/// 64-character hex string (32 bytes * 2)
///
/// # Examples
///
/// ```
/// use vigilnet_crypto::hash::blake3_hex;
///
/// let hash = blake3_hex(b"test");
/// assert_eq!(hash.len(), 64);
/// ```
pub fn blake3_hex(data: &[u8]) -> String {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize().to_hex().to_string()
}

/// Compute SHA-256 hash of data
///
/// SHA-256 is a widely-used cryptographic hash function.
/// Used in VigilNet for compatibility with existing systems.
///
/// # Arguments
///
/// * `data` - Input data to hash
///
/// # Returns
///
/// 32-byte hash as Vec<u8>
///
/// # Examples
///
/// ```
/// use vigilnet_crypto::hash::sha256;
///
/// let hash = sha256(b"test");
/// assert_eq!(hash.len(), 32);
/// ```
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute SHA-256 hash and return as hex string
///
/// # Arguments
///
/// * `data` - Input data to hash
///
/// # Returns
///
/// 64-character hex string
///
/// # Examples
///
/// ```
/// use vigilnet_crypto::hash::sha256_hex;
///
/// let hash = sha256_hex(b"test");
/// assert_eq!(hash.len(), 64);
/// ```
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_basic() {
        let data = b"Hello, world!";
        let hash = blake3(data);
        
        assert_eq!(hash.len(), 32); // BLAKE3 produces 32-byte hash
    }

    #[test]
    fn test_blake3_empty() {
        let hash1 = blake3(b"");
        let hash2 = blake3(b"");
        
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_blake3_deterministic() {
        let data = b"Test data";
        let hash1 = blake3(data);
        let hash2 = blake3(data);
        
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_blake3_different_data() {
        let hash1 = blake3(b"data1");
        let hash2 = blake3(b"data2");
        
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_blake3_large_data() {
        let data = vec![0xABu8; 100000];
        let hash = blake3(&data);
        
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_blake3_hex() {
        let data = b"Test";
        let hex_hash = blake3_hex(data);
        
        assert_eq!(hex_hash.len(), 64); // 32 bytes * 2 hex chars
        
        // Verify it's valid hex
        let bytes = hex::decode(&hex_hash).unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_blake3_hex_consistency() {
        let data = b"Consistent";
        let hex1 = blake3_hex(data);
        let hex2 = blake3_hex(data);
        
        assert_eq!(hex1, hex2);
    }

    #[test]
    fn test_sha256_basic() {
        let data = b"Hello, world!";
        let hash = sha256(data);
        
        assert_eq!(hash.len(), 32); // SHA256 produces 32-byte hash
    }

    #[test]
    fn test_sha256_empty() {
        let hash1 = sha256(b"");
        let hash2 = sha256(b"");
        
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_sha256_deterministic() {
        let data = b"Test data";
        let hash1 = sha256(data);
        let hash2 = sha256(data);
        
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_sha256_different_data() {
        let hash1 = sha256(b"data1");
        let hash2 = sha256(b"data2");
        
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_sha256_large_data() {
        let data = vec![0xABu8; 100000];
        let hash = sha256(&data);
        
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha256_hex() {
        let data = b"Test";
        let hex_hash = sha256_hex(data);
        
        assert_eq!(hex_hash.len(), 64); // 32 bytes * 2 hex chars
        
        // Verify it's valid hex
        let bytes = hex::decode(&hex_hash).unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_sha256_hex_consistency() {
        let data = b"Consistent";
        let hex1 = sha256_hex(data);
        let hex2 = sha256_hex(data);
        
        assert_eq!(hex1, hex2);
    }

    #[test]
    fn test_different_hashes_different_algorithms() {
        let data = b"Same data";
        let blake3_hash = blake3(data);
        let sha256_hash = sha256(data);
        
        // Different algorithms should produce different hashes
        assert_ne!(blake3_hash, sha256_hash);
    }

    #[test]
    fn test_known_sha256_values() {
        // SHA256 of empty string (known value)
        let empty_hash = sha256(b"");
        let expected = hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
        assert_eq!(empty_hash, expected);
    }

    #[test]
    fn test_binary_data_hashing() {
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        
        let blake3_hash = blake3(&data);
        let sha256_hash = sha256(&data);
        
        assert_eq!(blake3_hash.len(), 32);
        assert_eq!(sha256_hash.len(), 32);
    }

    #[test]
    fn test_unicode_hashing() {
        let data = "Hello 世界 🌍".as_bytes();
        
        let blake3_hash = blake3(data);
        let sha256_hash = sha256(data);
        
        assert_eq!(blake3_hash.len(), 32);
        assert_eq!(sha256_hash.len(), 32);
    }

    #[test]
    fn test_all_zeros_data() {
        let data = vec![0u8; 1000];
        let blake3_hash = blake3(&data);
        let sha256_hash = sha256(&data);
        
        assert_eq!(blake3_hash.len(), 32);
        assert_eq!(sha256_hash.len(), 32);
    }

    #[test]
    fn test_all_ones_data() {
        let data = vec![0xFFu8; 1000];
        let blake3_hash = blake3(&data);
        let sha256_hash = sha256(&data);
        
        assert_eq!(blake3_hash.len(), 32);
        assert_eq!(sha256_hash.len(), 32);
    }

    #[test]
    fn test_incrementing_data() {
        let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let blake3_hash = blake3(&data);
        let sha256_hash = sha256(&data);
        
        assert_eq!(blake3_hash.len(), 32);
        assert_eq!(sha256_hash.len(), 32);
    }

    #[test]
    fn test_single_byte_data() {
        for i in 0u8..=255 {
            let data = vec![i];
            let blake3_hash = blake3(&data);
            let sha256_hash = sha256(&data);
            
            assert_eq!(blake3_hash.len(), 32);
            assert_eq!(sha256_hash.len(), 32);
        }
    }

    #[test]
    fn test_very_small_data() {
        let sizes = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65];
        
        for size in sizes {
            let data = vec![0x42u8; size];
            let blake3_hash = blake3(&data);
            let sha256_hash = sha256(&data);
            
            assert_eq!(blake3_hash.len(), 32, "BLAKE3 failed for size {}", size);
            assert_eq!(sha256_hash.len(), 32, "SHA256 failed for size {}", size);
        }
    }

    #[test]
    fn test_hash_uniqueness() {
        let mut blake3_hashes = std::collections::HashSet::new();
        let mut sha256_hashes = std::collections::HashSet::new();
        
        for i in 0..100 {
            let data = format!("Unique data {}", i);
            
            let blake3_hash = blake3(data.as_bytes());
            let sha256_hash = sha256(data.as_bytes());
            
            assert!(blake3_hashes.insert(blake3_hash), "BLAKE3 collision at iteration {}", i);
            assert!(sha256_hashes.insert(sha256_hash), "SHA256 collision at iteration {}", i);
        }
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = b"Roundtrip test";
        
        let blake3_hex_str = blake3_hex(data);
        let blake3_bytes = hex::decode(&blake3_hex_str).unwrap();
        assert_eq!(blake3_bytes, blake3(data));
        
        let sha256_hex_str = sha256_hex(data);
        let sha256_bytes = hex::decode(&sha256_hex_str).unwrap();
        assert_eq!(sha256_bytes, sha256(data));
    }

    #[test]
    fn test_hex_lowercase() {
        let data = b"Case test";
        let blake3_hex_str = blake3_hex(data);
        let sha256_hex_str = sha256_hex(data);
        
        // Hex strings should be lowercase
        assert_eq!(blake3_hex_str, blake3_hex_str.to_lowercase());
        assert_eq!(sha256_hex_str, sha256_hex_str.to_lowercase());
    }
}
