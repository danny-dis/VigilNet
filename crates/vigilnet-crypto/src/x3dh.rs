//! Extended Triple Diffie-Hellman (X3DH) Key Agreement Protocol
//!
//! X3DH establishes a shared secret between two parties using:
//! - Identity Keys (IK): Long-term X25519 keys
//! - Signed Pre-Keys (SPK): Medium-term keys signed by IK
//! - One-Time Pre-Keys (OPK): Single-use keys for additional forward secrecy

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::{debug, info};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{CryptoError, Result};

const INFO_X3DH: &[u8] = b"VigilNet-X3DH-v1";
const SALT: &[u8] = b"VigilNet-E2EE-Salt";

/// Identity Key Pair (long-term key)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityKeyPair {
    /// X25519 secret key
    pub secret: [u8; 32],
    /// X25519 public key
    pub public: [u8; 32],
    /// Ed25519 signing key for SPK signing
    #[serde(skip)]
    signing_key: Option<SigningKey>,
    /// Ed25519 verifying key (for SPK verification)
    pub identity_public: [u8; 32],
}

impl IdentityKeyPair {
    /// Generate a new identity key pair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let identity_public = signing_key.verifying_key().to_bytes();

        Self {
            secret: secret.to_bytes(),
            public: public.to_bytes(),
            signing_key: Some(signing_key),
            identity_public,
        }
    }

    /// Create from existing keys
    pub fn from_keys(secret: [u8; 32], signing_key: SigningKey) -> Self {
        let secret = StaticSecret::from(secret);
        let public = PublicKey::from(&secret);
        let identity_public = signing_key.verifying_key().to_bytes();

        Self {
            secret,
            public: public.to_bytes(),
            signing_key: Some(signing_key),
            identity_public,
        }
    }

    /// Get public key
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(self.secret.as_slice().try_into().unwrap())
    }

    /// Get secret key
    pub fn secret_key(&self) -> StaticSecret {
        StaticSecret::from(self.secret)
    }

    /// Get Ed25519 verifying key
    pub fn identity_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.identity_public).unwrap()
    }

    /// Sign data with identity key
    pub fn sign(&self, data: &[u8]) -> Option<ed25519_dalek::Signature> {
        self.signing_key.as_ref().map(|sk| sk.sign(data))
    }
}

/// Signed Pre-Key (medium-term key, rotated periodically)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedPreKey {
    /// Key ID for this pre-key
    pub id: u32,
    /// X25519 public key
    pub public: [u8; 32],
    /// X25519 secret key
    #[serde(skip)]
    pub secret: Option<[u8; 32]>,
    /// Ed25519 signature over SPK public key
    pub signature: [u8; 64],
    /// Timestamp when signed
    pub timestamp: u64,
}

impl SignedPreKey {
    /// Generate and sign a new signed pre-key
    pub fn generate(identity_key: &IdentityKeyPair, id: u32) -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        let mut data = public.as_bytes().to_vec();
        data.extend_from_slice(&id.to_le_bytes());
        let signature = identity_key.sign(&data).unwrap();

        Self {
            id,
            public: public.to_bytes(),
            secret: Some(secret.to_bytes()),
            signature: signature.to_bytes(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Verify the signature on this pre-key
    pub fn verify(&self, identity_key: &VerifyingKey) -> bool {
        let mut data = self.public.to_vec();
        data.extend_from_slice(&self.id.to_le_bytes());
        let signature = ed25519_dalek::Signature::from_bytes(&self.signature);
        identity_key.verify(&data, &signature).is_ok()
    }

    /// Get public key
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(self.public.as_slice().try_into().unwrap())
    }

    /// Get secret key (if available)
    pub fn secret_key(&self) -> Option<StaticSecret> {
        self.secret.map(StaticSecret::from)
    }
}

/// One-Time Pre-Key (single-use key for additional forward secrecy)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OneTimePreKey {
    /// Key ID
    pub id: u32,
    /// X25519 public key
    pub public: [u8; 32],
    /// X25519 secret key (only needed server-side)
    #[serde(skip)]
    pub secret: Option<[u8; 32]>,
}

impl OneTimePreKey {
    /// Generate a new one-time pre-key
    pub fn generate(id: u32) -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        Self {
            id,
            public: public.to_bytes(),
            secret: Some(secret.to_bytes()),
        }
    }

    /// Get public key
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(self.public.as_slice().try_into().unwrap())
    }

    /// Get secret key
    pub fn secret_key(&self) -> Option<StaticSecret> {
        self.secret.map(StaticSecret::from)
    }
}

/// Pre-Key Bundle for X3DH initialization
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreKeyBundle {
    /// Recipient's identity public key
    pub identity_key: [u8; 32],
    /// Signed pre-key
    pub signed_prekey: SignedPreKey,
    /// One-time pre-key (optional)
    pub one_time_prekey: Option<OneTimePreKey>,
}

impl PreKeyBundle {
    /// Create a new pre-key bundle from identity keys
    pub fn new(
        identity_key: &IdentityKeyPair,
        signed_prekey: SignedPreKey,
        one_time_prekey: Option<OneTimePreKey>,
    ) -> Self {
        Self {
            identity_key: identity_key.public,
            signed_prekey,
            one_time_prekey,
        }
    }
}

/// X3DH Key Agreement Protocol
pub struct X3DH;

impl X3DH {
    /// Initialize X3DH as the initiator (Alice)
    ///
    /// Returns: (ephemeral_key, initial_message, derived_shared_secret)
    pub fn initiator_initiate(
        bundle: &PreKeyBundle,
    ) -> Result<(X3DHInitiatorState, [u8; 32], Vec<u8>)> {
        debug!("Initiating X3DH as Alice");

        let mut os_rng = OsRng;
        let mut ephemeral_secret = [0u8; 32];
        os_rng.fill_bytes(&mut ephemeral_secret);
        let ephemeral_secret = StaticSecret::from(ephemeral_secret);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        let identity_secret = StaticSecret::random_from_rng(OsRng);
        let identity_public = PublicKey::from(&identity_secret);

        let spk_public = PublicKey::from(bundle.signed_prekey.public.as_slice().try_into().unwrap());

        let dh1 = identity_secret.diffie_hellman(&spk_public);
        let dh2 = ephemeral_secret.diffie_hellman(&PublicKey::from(
            bundle.identity_key.as_slice().try_into().unwrap(),
        ));
        let dh3 = ephemeral_secret.diffie_hellman(&spk_public);

        let mut dh_output = [0u8; 96];
        dh_output[..32].copy_from_slice(dh1.as_bytes());
        dh_output[32..64].copy_from_slice(dh2.as_bytes());
        dh_output[64..96].copy_from_slice(dh3.as_bytes());

        let ikm = if let Some(ref otpk) = bundle.one_time_prekey {
            let dh4 = ephemeral_secret.diffie_hellman(&PublicKey::from(
                otpk.public.as_slice().try_into().unwrap(),
            ));
            let mut extended = [0u8; 128];
            extended[..96].copy_from_slice(&dh_output);
            extended[96..128].copy_from_slice(dh4.as_bytes());
            extended
        } else {
            dh_output
        };

        let shared_secret = Self::derive_key(&ikm);
        let info = Self::build_info(&identity_public, &spk_public);

        let mut message = Vec::new();
        message.extend_from_slice(identity_public.as_bytes());
        message.extend_from_slice(ephemeral_public.as_bytes());
        message.extend_from_slice(&bundle.signed_prekey.id.to_le_bytes());
        if let Some(ref otpk) = bundle.one_time_prekey {
            message.extend_from_slice(&otpk.id.to_le_bytes());
        }

        let state = X3DHInitiatorState {
            identity_secret,
            identity_public,
            ephemeral_secret,
            ephemeral_public,
            used_otpk_id: bundle.one_time_prekey.as_ref().map(|otpk| otpk.id),
        };

        info!("X3DH initiator established shared secret");
        Ok((state, shared_secret, message))
    }

    /// Respond to X3DH as Bob (server-side)
    pub fn responder_initiate(
        identity_key: &IdentityKeyPair,
        signed_prekey: &SignedPreKey,
        one_time_prekey: Option<&OneTimePreKey>,
        initiator_identity: [u8; 32],
        initiator_ephemeral: [u8; 32],
    ) -> Result<[u8; 32]> {
        debug!("Responding to X3DH as Bob");

        let initiator_identity = PublicKey::from(initiator_identity.as_slice().try_into().unwrap());
        let initiator_ephemeral = PublicKey::from(initiator_ephemeral.as_slice().try_into().unwrap());
        let spk_secret = signed_prekey
            .secret_key()
            .ok_or_else(|| CryptoError::X3DHFailed("SPK secret not available".to_string()))?;

        let dh1 = spk_secret.diffie_hellman(&initiator_identity);
        let dh2 = identity_key
            .secret_key()
            .diffie_hellman(&initiator_ephemeral);
        let dh3 = spk_secret.diffie_hellman(&initiator_ephemeral);

        let mut dh_output = [0u8; 96];
        dh_output[..32].copy_from_slice(dh1.as_bytes());
        dh_output[32..64].copy_from_slice(dh2.as_bytes());
        dh_output[64..96].copy_from_slice(dh3.as_bytes());

        let ikm = if let Some(otpk) = one_time_prekey {
            let otpk_secret = otpk
                .secret_key()
                .ok_or_else(|| CryptoError::X3DHFailed("OTPK secret not available".to_string()))?;
            let dh4 = otpk_secret.diffie_hellman(&initiator_ephemeral);
            let mut extended = [0u8; 128];
            extended[..96].copy_from_slice(&dh_output);
            extended[96..128].copy_from_slice(dh4.as_bytes());
            extended
        } else {
            dh_output
        };

        let shared_secret = Self::derive_key(&ikm);

        info!("X3DH responder established shared secret");
        Ok(shared_secret)
    }

    fn derive_key(ikm: &[u8]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(SALT), ikm);
        let mut okm = [0u8; 32];
        hk.expand(INFO_X3DH, &mut okm).unwrap();
        okm
    }

    fn build_info(identity: &PublicKey, spk: &PublicKey) -> Vec<u8> {
        let mut info = Vec::new();
        info.extend_from_slice(identity.as_bytes());
        info.extend_from_slice(spk.as_bytes());
        info
    }
}

/// State held by X3DH initiator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct X3DHInitiatorState {
    identity_secret: StaticSecret,
    identity_public: PublicKey,
    ephemeral_secret: StaticSecret,
    ephemeral_public: PublicKey,
    used_otpk_id: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_key_generation() {
        let ik = IdentityKeyPair::generate();
        assert_eq!(ik.public.len(), 32);
        assert_eq!(ik.identity_public.len(), 32);
    }

    #[test]
    fn test_signed_prekey() {
        let ik = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(&ik, 1);

        assert!(spk.verify(&ik.identity_key()));
    }

    #[test]
    fn test_signed_prekey_verification_fails_with_wrong_key() {
        let ik = IdentityKeyPair::generate();
        let wrong_ik = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(&ik, 1);

        assert!(!spk.verify(&wrong_ik.identity_key()));
    }

    #[test]
    fn test_one_time_prekey() {
        let otpk = OneTimePreKey::generate(1);
        assert_eq!(otpk.id, 1);
        assert_eq!(otpk.public.len(), 32);
    }

    #[test]
    fn test_x3dh_key_agreement() {
        let alice_ik = IdentityKeyPair::generate();
        let bob_ik = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(&bob_ik, 1);
        let bob_otpk = OneTimePreKey::generate(1);

        let bundle = PreKeyBundle {
            identity_key: bob_ik.identity_public,
            signed_prekey: bob_spk.clone(),
            one_time_prekey: Some(bob_otpk.clone()),
        };

        let (alice_state, alice_secret, alice_msg) =
            X3DH::initiator_initiate(&bundle).unwrap();

        let bob_secret = X3DH::responder_initiate(
            &bob_ik,
            &bob_spk,
            Some(&bob_otpk),
            alice_msg[0..32].try_into().unwrap(),
            alice_msg[32..64].try_into().unwrap(),
        )
        .unwrap();

        assert_eq!(alice_secret, bob_secret);
    }

    #[test]
    fn test_x3dh_without_otpk() {
        let alice_ik = IdentityKeyPair::generate();
        let bob_ik = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(&bob_ik, 1);

        let bundle = PreKeyBundle {
            identity_key: bob_ik.identity_public,
            signed_prekey: bob_spk.clone(),
            one_time_prekey: None,
        };

        let (alice_state, alice_secret, alice_msg) =
            X3DH::initiator_initiate(&bundle).unwrap();

        let bob_secret = X3DH::responder_initiate(
            &bob_ik,
            &bob_spk,
            None,
            alice_msg[0..32].try_into().unwrap(),
            alice_msg[32..64].try_into().unwrap(),
        )
        .unwrap();

        assert_eq!(alice_secret, bob_secret);
    }

    #[test]
    fn test_prekey_bundle_serialization() {
        let bob_ik = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(&bob_ik, 1);
        let bob_otpk = OneTimePreKey::generate(1);

        let bundle = PreKeyBundle {
            identity_key: bob_ik.identity_public,
            signed_prekey: bob_spk.clone(),
            one_time_prekey: Some(bob_otpk.clone()),
        };

        let serialized = serde_json::to_vec(&bundle).unwrap();
        let deserialized: PreKeyBundle = serde_json::from_slice(&serialized).unwrap();

        assert_eq!(bundle.identity_key, deserialized.identity_key);
        assert_eq!(bundle.signed_prekey.id, deserialized.signed_prekey.id);
    }
}
