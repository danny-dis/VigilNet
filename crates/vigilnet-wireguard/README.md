# VigilNet WireGuard

WireGuard tunnel integration for VigilNet.

## Overview

`vigilnet-wireguard` provides WireGuard VPN tunneling:

- **Fast Encryption**: ChaCha20-Poly1305 authenticated encryption
- **Modern Crypto**: Curve25519 ECDH, BLAKE2s, SipHash
- **Userspace Implementation**: Cross-platform via boringtun
- **E2EE**: Signal Protocol on top of WireGuard

## Quick Start

```rust
use vigilnet_wireguard::{WireGuardConfig, PeerConfig, WireGuardTransport};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure WireGuard
    let config = WireGuardConfig {
        private_key: "base64-encoded-private-key".to_string(),
        listen_port: 51820,
        peers: vec![
            PeerConfig {
                public_key: "peer-public-key".to_string(),
                endpoint: Some("peer.example.com:51820".to_string()),
                allowed_ips: vec!["10.0.0.2/32".to_string()],
                persistent_keepalive: Some(25),
            },
        ],
    };
    
    // Create transport
    let transport = WireGuardTransport::new(config);
    transport.start().await?;
    
    println!("WireGuard tunnel active");
    
    Ok(())
}
```

## Configuration

### WireGuard Config

```rust
use vigilnet_wireguard::{WireGuardConfig, PeerConfig};

let config = WireGuardConfig {
    private_key: "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=".to_string(),
    listen_port: 51820,
    fwmark: None,
    peers: vec![
        PeerConfig {
            public_key: "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=".to_string(),
            preshared_key: None,
            endpoint: Some("192.95.5.69:51820".to_string()),
            persistent_keepalive: Some(25),
            allowed_ips: vec![
                "10.0.0.2/32".to_string(),
                "fd00::2/128".to_string(),
            ],
        },
    ],
};
```

### Generate Keys

```rust
use vigilnet_wireguard::WgTunnel;

// Generate private key
let private_key = WgTunnel::generate_private_key();
let public_key = WgTunnel::derive_public_key(&private_key);

println!("Private: {}", base64::encode(&private_key));
println!("Public: {}", base64::encode(&public_key));
```

## Tunnel Management

### Create Tunnel

```rust
use vigilnet_wireguard::WgTunnel;

let mut tunnel = WgTunnel::new()
    .with_private_key(private_key)
    .with_peer_key(peer_public_key)
    .with_endpoint("peer.example.com:51820")
    .with_allowed_ips(vec!["10.0.0.0/24".to_string()])
    .with_keepalive(25);

tunnel.start().await?;
```

### Tunnel State

```rust
use vigilnet_wireguard::TunnelState;

match tunnel.state() {
    TunnelState::Down => println!("Tunnel down"),
    TunnelState::Handshaking => println!("Handshaking..."),
    TunnelState::Up => println!("Tunnel active"),
    TunnelState::Error(e) => println!("Error: {}", e),
}
```

### Statistics

```rust
let stats = tunnel.stats();
println!("Bytes sent: {}", stats.tx_bytes);
println!("Bytes received: {}", stats.rx_bytes);
println!("Handshakes: {}", stats.handshakes);
```

## E2EE over WireGuard

```rust
use vigilnet_crypto::PreKeyBundle;

let mut transport = WireGuardTransport::new(config);
transport.enable_e2ee(prekey_bundle)?;
```

## Transport Integration

```rust
use vigilnet_agent_transport::AgentTransport;

#[async_trait]
impl AgentTransport for WireGuardTransport {
    async fn bind(&mut self) -> TransportResult<()> {
        self.start().await
            .map_err(|e| TransportError::Bind(e.to_string()))
    }
    
    async fn connect(&self, addr: SocketAddr) -> TransportResult<Box<dyn AgentConnection>> {
        // Connect via WireGuard tunnel
    }
    
    // ... other methods
}
```

## Why WireGuard?

- **Performance**: Kernel-level speed in userspace
- **Simplicity**: ~4,000 lines of code vs 400,000+ for IPsec/OpenVPN
- **Modern Crypto**: No legacy algorithms
- **Roaming**: Seamlessly handles IP changes
- **Minimal Configuration**: Single keypair per peer

## Protocol Details

### Crypto

- **Handshake**: Noise_IK pattern with Curve25519
- **Encryption**: ChaCha20-Poly1305 AEAD
- **Hashing**: BLAKE2s
- **Key Derivation**: HKDF

### Packet Format

1. **Handshake Initiation**: 148 bytes
2. **Handshake Response**: 92 bytes
3. **Transport Data**: Variable + 16 byte auth tag

## Error Handling

```rust
pub enum WgError {
    TunnelFailed(String),
    PeerError(String),
    HandshakeFailed(String),
    CryptoError(String),
    ConnectionFailed(String),
}
```

## Integration

Used by:
- `vigilnet-core`: As a routing backend
- `vigilnet-android`: Android VPN
- `vigilnet-agent-transport`: Agent network transport

## License

GPL-3.0
