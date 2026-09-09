# VigilNet Cryptography

Cryptographic primitives and protocols for the VigilNet privacy network.

## Overview

`vigilnet-crypto` provides all cryptographic functionality used throughout VigilNet:

- **Identity & Session Keys**: Ed25519 and X25519 key management
- **Onion Encryption**: Multi-layer AES-GCM encryption for anonymous routing
- **Signal Protocol**: End-to-end encryption via X3DH and Double Ratchet
- **Hash Functions**: BLAKE3 and SHA-256 utilities

## Features

- `simd` (default): Enable hardware-accelerated AES-GCM encryption

## Modules

### `aead` - Authenticated Encryption

AES-256-GCM encryption with optimized performance:

```rust
use vigilnet_crypto::{encrypt, decrypt};

let key = [0x42u8; 32];
let plaintext = b"Secret message";

// Encrypt
let ciphertext = encrypt(&key, plaintext)?;

// Decrypt
let decrypted = decrypt(&key, &ciphertext)?;
assert_eq!(plaintext.as_slice(), decrypted.as_slice());
```

### `keys` - Key Management

Generate and manage identity and session keys:

```rust
use vigilnet_crypto::{Identity, SessionKey};

// Generate Ed25519 identity
let identity = Identity::generate();
let public_key = identity.public_key();

// Generate X25519 keypair for session encryption
let (secret, public) = SessionKey::generate_static();
```

### `onion` - Onion Routing

Multi-layer encryption for anonymous circuits:

```rust
use vigilnet_crypto::{OnionPacket, OnionLayer, SessionKey};

// Create encryption layers for a 3-hop circuit
let layers: Vec<OnionLayer> = (0..3)
    .map(|i| OnionLayer {
        key: SessionKey::from_shared_secret([i as u8; 32]),
        hop_id: [i as u8; 32],
    })
    .collect();

// Wrap payload in onion layers
let payload = b"Hello, anonymous world!";
let packet = OnionPacket::wrap(payload, &layers, 12345)?;

// Each hop unwraps one layer
let mut data = packet.payload;
for layer in &layers {
    data = vigilnet_crypto::decrypt(layer.key.as_bytes(), &data)?;
}
```

### `x3dh` - X3DH Key Agreement

Extended Triple Diffie-Hellman for initial key exchange:

```rust
use vigilnet_crypto::{IdentityKeyPair, SignedPreKey, OneTimePreKey, X3DH, PreKeyBundle};

// Bob generates keys
let bob_ik = IdentityKeyPair::generate();
let bob_spk = SignedPreKey::generate(&bob_ik, 1);
let bob_otpk = OneTimePreKey::generate(1);

// Create pre-key bundle
let bundle = PreKeyBundle::new(&bob_ik, bob_spk.clone(), Some(bob_otpk.clone()));

// Alice initiates X3DH
let (alice_state, shared_secret, message) = X3DH::initiator_initiate(&bundle)?;

// Bob responds
let bob_secret = X3DH::responder_initiate(
    &bob_ik,
    &bob_spk,
    Some(&bob_otpk),
    message[0..32].try_into()?,
    message[32..64].try_into()?,
)?;

// Both have the same shared secret
assert_eq!(shared_secret, bob_secret);
```

### `ratchet` - Double Ratchet Algorithm

Forward-secure messaging with automatic key rotation:

```rust
use vigilnet_crypto::ratchet::DoubleRatchet;

let shared_secret = [0x42u8; 32];

// Alice creates ratchet as initiator
let mut alice = DoubleRatchet::initiator(shared_secret, [0x43u8; 32]);

// Bob creates ratchet as responder
let mut bob = DoubleRatchet::responder(shared_secret);

// Perform initial DH ratchet exchange
alice.dh_ratchet(&bob.sending_public_key())?;
bob.dh_ratchet(&alice.sending_public_key())?;

// Encrypt/decrypt messages
let plaintext = b"Hello, secure world!";
let encrypted = alice.encrypt(plaintext)?;
let decrypted = bob.decrypt(&encrypted.header, &encrypted.ciphertext)?;

assert_eq!(plaintext.as_slice(), decrypted.as_slice());
```

### `session` - E2EE Session Management

High-level session management combining X3DH and Double Ratchet:

```rust
use vigilnet_crypto::session::Session;

// Create session as initiator
let (mut alice_session, prekey_msg) = Session::create_initiator(&bundle, peer_identity)?;

// Create session as responder
let mut bob_session = Session::create_responder(
    &bob_ik, &bob_spk, Some(&bob_otpk),
    identity_key, ephemeral_key, spk_id, otpk_id
)?;

// Encrypt and decrypt messages
let plaintext = b"Secret message";
let encrypted = alice_session.encrypt(plaintext)?;
let decrypted = bob_session.decrypt(&encrypted)?;
```

### `hash` - Hash Functions

```rust
use vigilnet_crypto::{blake3, blake3_hex, sha256, sha256_hex};

let data = b"Hello, world!";

// BLAKE3 (fast, modern hash)
let hash = blake3(data);
let hex_hash = blake3_hex(data);

// SHA-256 (compatibility)
let hash = sha256(data);
let hex_hash = sha256_hex(data);
```

## Security Features

- **AES-256-GCM**: Authenticated encryption with 256-bit keys
- **X25519 ECDH**: Modern elliptic curve Diffie-Hellman
- **Ed25519**: High-security digital signatures
- **Signal Protocol**: Industry-standard E2EE with forward secrecy
- **BLAKE3**: Fast, secure hashing

## Performance

- Hardware-accelerated AES when available (AES-NI)
- Thread-local cipher caching for high-throughput scenarios
- SIMD optimizations for encryption/decryption

## License

GPL-3.0
