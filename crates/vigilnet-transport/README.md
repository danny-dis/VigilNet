# VigilNet Transport

Network transport layer for the VigilNet privacy network.

## Overview

`vigilnet-transport` provides multiple transport protocols:

- **TCP**: Traditional TCP with Noise encryption
- **QUIC**: Modern UDP-based transport with built-in encryption
- **BLE**: Bluetooth Low Energy for offline/mesh fallback
- **SecureTransport**: Signal Protocol E2EE wrapper

## Quick Start

```rust
use vigilnet_transport::{TransportConfig, ConnectionStats};

// Configure transport
let config = TransportConfig::default();

// Track connection statistics
let stats = ConnectionStats::new();
stats.record_sent(1024).await;
stats.record_received(512).await;

let snapshot = stats.stats().await;
println!("Sent: {} bytes", snapshot.bytes_sent);
```

## TCP Transport

Traditional TCP transport with Noise protocol encryption:

```rust
use vigilnet_transport::TcpTransport;

let transport = TcpTransport::new("127.0.0.1:8080");
transport.start()?;
```

## QUIC Transport

Modern QUIC transport for better NAT traversal:

```rust
use vigilnet_transport::QuicTransport;

let transport = QuicTransport::new("127.0.0.1:4433");
transport.start()?;
```

## BLE Transport

Bluetooth Low Energy for offline communication:

```rust
use vigilnet_transport::BleTransport;

let transport = BleTransport::new();
transport.start()?;
```

## Secure Transport

Signal Protocol E2EE wrapper for any transport:

```rust
use vigilnet_transport::SecureTransport;

let secure = SecureTransport::new(Box::new(transport));
secure.enable_e2ee(prekey_bundle)?;
```

## Transport Traits

All transports implement common traits:

```rust
pub trait Transport: Send + Sync {
    fn start(&self) -> TransportResult<()>;
    fn stop(&self) -> TransportResult<()>;
    fn is_running(&self) -> bool;
    fn local_peer_id(&self) -> Option<String>;
}

pub trait Connection: Send + Sync {
    fn peer_id(&self) -> &str;
    fn is_connected(&self) -> bool;
    fn close(&self) -> TransportResult<()>;
}

pub trait MessageSink: Send + Sync {
    fn send(&self, peer_id: &str, data: &[u8]) -> TransportResult<()>;
    fn broadcast(&self, data: &[u8]) -> TransportResult<()>;
}
```

## Configuration

```rust
let config = TransportConfig {
    max_connections: 256,
    connection_timeout_ms: 30_000,
    read_buffer_size: 64 * 1024,
    write_buffer_size: 64 * 1024,
    keepalive_interval_ms: 30_000,
    max_message_size: 10 * 1024 * 1024,
    rate_limit_per_sec: 1000,
};
```

## Error Handling

Comprehensive error types:

- `ConnectionFailed`: Could not establish connection
- `NotAvailable`: Transport not supported on this platform
- `Timeout`: Operation timed out
- `PeerNotFound`: Unknown peer
- `Session`: E2EE session error
- `RateLimited`: Too many messages

## Integration

Used by:
- `vigilnet-core`: Node transport layer
- `vigilnet-agent-transport`: Agent network transports
- `vigilnet-android`: Mobile transport

## License

GPL-3.0
