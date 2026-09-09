//! Performance Benchmarks for VigilNet
//!
//! Run with: cargo bench --workspace

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};

// ============== Cryptographic Benchmarks ==============

fn bench_aes_gcm(c: &mut Criterion) {
    use vigilnet_crypto::{encrypt, generate_encryption_key};
    
    let key = generate_encryption_key();
    let mut group = c.benchmark_group("aes_gcm_encrypt");
    
    for size in [1024, 1024 * 1024, 10 * 1024 * 1024].iter() {
        let data = vec![0u8; *size];
        let aad = b"benchmark";
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let _ = encrypt(black_box(&key), black_box(&data), black_box(aad));
            });
        });
    }
    
    group.finish();
}

fn bench_x25519(c: &mut Criterion) {
    use vigilnet_crypto::{generate_ephemeral_keypair, x25519_dh};
    
    c.bench_function("x25519_keygen", |b| {
        b.iter(|| {
            let _ = generate_ephemeral_keypair();
        });
    });
    
    let (sk1, pk1) = generate_ephemeral_keypair();
    let (sk2, pk2) = generate_ephemeral_keypair();
    
    c.bench_function("x25519_dh", |b| {
        b.iter(|| {
            let _ = x25519_dh(black_box(&sk1), black_box(&pk2));
            let _ = x25519_dh(black_box(&sk2), black_box(&pk1));
        });
    });
}

fn bench_ed25519(c: &mut Criterion) {
    use vigilnet_crypto::{generate_signing_keypair, sign, verify};
    
    let (sk, pk) = generate_signing_keypair();
    let message = b"benchmark message";
    let signature = sign(&sk, message);
    
    let mut group = c.benchmark_group("ed25519");
    
    group.bench_function("sign", |b| {
        b.iter(|| {
            let _ = sign(black_box(&sk), black_box(message));
        });
    });
    
    group.bench_function("verify", |b| {
        b.iter(|| {
            let _ = verify(black_box(&pk), black_box(message), black_box(&signature));
        });
    });
    
    group.finish();
}

fn bench_x3dh(c: &mut Criterion) {
    use vigilnet_crypto::x3dh::{X3DH, IdentityKeyPair, OneTimePreKey, SignedPreKey};
    
    let mut group = c.benchmark_group("x3dh");
    
    // Setup keys
    let alice_identity = IdentityKeyPair::generate();
    let bob_identity = IdentityKeyPair::generate();
    let bob_signed_prekey = SignedPreKey::generate(&bob_identity, 1);
    let bob_otpk = OneTimePreKey::generate(0);
    
    group.bench_function("initiate", |b| {
        b.iter(|| {
            let _ = X3DH::initiate(
                black_box(&alice_identity),
                black_box(&bob_identity.identity_public),
                black_box(&bob_signed_prekey),
                black_box(Some(&bob_otpk)),
            );
        });
    });
    
    // Pre-calculate initial message for responder benchmark
    let (initial_message, _) = X3DH::initiate(
        &alice_identity,
        &bob_identity.identity_public,
        &bob_signed_prekey,
        Some(&bob_otpk),
    ).unwrap();
    
    group.bench_function("respond", |b| {
        b.iter(|| {
            let _ = X3DH::respond(
                black_box(&bob_identity),
                black_box(&bob_signed_prekey),
                black_box(&initial_message),
            );
        });
    });
    
    group.finish();
}

fn bench_double_ratchet(c: &mut Criterion) {
    use vigilnet_crypto::{DoubleRatchet, SessionKey};
    
    let mut group = c.benchmark_group("double_ratchet");
    
    let sk = SessionKey::generate();
    let (mut alice_ratchet, mut bob_ratchet) = DoubleRatchet::init_alice_bob(&sk);
    
    // Do initial exchange to set up ratchet
    let _ = alice_ratchet.encrypt(b"initial");
    
    group.bench_function("encrypt", |b| {
        b.iter(|| {
            let _ = alice_ratchet.encrypt(black_box(b"test message"));
        });
    });
    
    let encrypted = alice_ratchet.encrypt(b"test");
    
    group.bench_function("decrypt", |b| {
        b.iter(|| {
            let _ = bob_ratchet.decrypt(black_box(&encrypted));
        });
    });
    
    group.finish();
}

fn bench_onion_encryption(c: &mut Criterion) {
    use vigilnet_crypto::onion::{OnionPacket, CircuitHop};
    
    let mut group = c.benchmark_group("onion");
    
    // Create test circuit with 3 hops
    let hops: Vec<CircuitHop> = (0..3).map(|i| CircuitHop {
        public_key: [i as u8; 32],
        address: format!("hop{}", i),
    }).collect();
    
    let payload = vec![0u8; 1024];
    
    group.bench_function("create_3hop", |b| {
        b.iter(|| {
            let _ = OnionPacket::create(
                black_box(&hops),
                black_box(&payload),
            );
        });
    });
    
    let packet = OnionPacket::create(&hops, &payload).unwrap();
    
    group.bench_function("peel_3hop", |b| {
        b.iter(|| {
            let mut p = packet.clone();
            for _ in 0..3 {
                if let Ok((_, _)) = p.peel(black_box(&[0u8; 32])) {
                    // Continue peeling
                }
            }
        });
    });
    
    group.finish();
}

// ============== Agent Benchmarks ==============

fn bench_agent_message(c: &mut Criterion) {
    use vigilnet_agent_core::{AgentBuilder, ConnectionPoolConfig};
    
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("agent_message");
    
    group.bench_function("create_agent", |b| {
        b.to_async(&rt).iter(|| async {
            let _ = AgentBuilder::new()
                .name("benchmark")
                .build()
                .await
                .unwrap();
        });
    });
    
    group.bench_function("create_with_pool", |b| {
        b.to_async(&rt).iter(|| async {
            let _ = AgentBuilder::new()
                .name("benchmark")
                .connection_pool_config(ConnectionPoolConfig::default())
                .build()
                .await
                .unwrap();
        });
    });
    
    group.finish();
}

// ============== Transport Benchmarks ==============

fn bench_message_serialization(c: &mut Criterion) {
    use vigilnet_agent_core::message::{Message, MessageType, MessageFlags};
    
    let message = Message::new(
        MessageType::Data,
        vec![0u8; 1024],
        MessageFlags::ENCRYPTED | MessageFlags::COMPRESSED,
    );
    
    c.bench_function("message_serialize", |b| {
        b.iter(|| {
            let _ = black_box(&message).serialize();
        });
    });
    
    let serialized = message.serialize();
    
    c.bench_function("message_deserialize", |b| {
        b.iter(|| {
            let _ = Message::deserialize(black_box(&serialized));
        });
    });
}

// ============== Circle Benchmarks ==============

fn bench_shamir_secret_sharing(c: &mut Criterion) {
    use vigilnet_agent_circles::ShamirSecretSharing;
    
    let mut group = c.benchmark_group("shamir");
    
    let secret = b"this is a secret message for testing";
    
    for (k, n) in [(2, 3), (3, 5), (5, 10)].iter() {
        let sss = ShamirSecretSharing::new(*k, *n);
        
        group.bench_with_input(
            BenchmarkId::new("split", format!("{}of{}", k, n)),
            &(*k, *n),
            |b, _| {
                b.iter(|| {
                    let _ = sss.split(black_box(secret));
                });
            },
        );
        
        let shares = sss.split(secret);
        
        group.bench_with_input(
            BenchmarkId::new("reconstruct", format!("{}of{}", k, n)),
            &(*k, *n),
            |b, _| {
                b.iter(|| {
                    let subset = &shares[0..*k];
                    let _ = sss.reconstruct(black_box(subset));
                });
            },
        );
    }
    
    group.finish();
}

// ============== Throughput Benchmarks ==============

fn bench_throughput(c: &mut Criterion) {
    use vigilnet_crypto::{encrypt, generate_encryption_key};
    
    let mut group = c.benchmark_group("throughput");
    group.sample_size(10);
    
    let key = generate_encryption_key();
    let data = vec![0u8; 10 * 1024 * 1024]; // 10 MB
    let aad = b"throughput_test";
    
    group.throughput(Throughput::Bytes(10 * 1024 * 1024));
    group.bench_function("encrypt_10mb", |b| {
        b.iter(|| {
            let _ = encrypt(&key, &data, aad);
        });
    });
    
    group.finish();
}

// ============== Benchmark Groups ==============

criterion_group!(
    crypto_benchmarks,
    bench_aes_gcm,
    bench_x25519,
    bench_ed25519,
    bench_x3dh,
    bench_double_ratchet,
    bench_onion_encryption,
);

criterion_group!(
    agent_benchmarks,
    bench_agent_message,
    bench_message_serialization,
);

criterion_group!(
    circle_benchmarks,
    bench_shamir_secret_sharing,
);

criterion_group!(
    throughput_benchmarks,
    bench_throughput,
);

criterion_main!(
    crypto_benchmarks,
    agent_benchmarks,
    circle_benchmarks,
    throughput_benchmarks,
);
