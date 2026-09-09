# VigilNet Agent Transport

Transport layer for the VigilNet agent network.

## Overview

`vigilnet-agent-transport` provides network transport implementations:

- **TCP**: Reliable stream transport
- **QUIC**: Modern UDP-based transport
- **BLE**: Bluetooth Low Energy for mesh
- **Unified**: Transport abstraction layer

## Quick Start

```rust
use vigilnet_agent_transport::{AgentTransport, TcpAgentTransport, TcpConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create TCP transport
    let config = TcpConfig {
        bind_addr: "0.0.0.0:0".parse()?,
        keepalive_secs: 30,
    };
    
    let mut transport = TcpAgentTransport::new(config);
    
    // Bind and start
    transport.bind().await?;
    
    // Connect to peer
    let conn = transport.connect("192.168.1.100:8080".parse()?).await?;
    
    Ok(())
}
```

## Transport Types

### TCP Transport

```rust
use vigilnet_agent_transport::{TcpAgentTransport, TcpConfig};

let config = TcpConfig {
    bind_addr: "0.0.0.0:8080".parse()?,
    keepalive_secs: 30,
    nodelay: true,
};

let transport = TcpAgentTransport::new(config);
```

### QUIC Transport

```rust
use vigilnet_agent_transport::{QuicAgentTransport, QuicConfig};

let config = QuicConfig {
    bind_addr: "0.0.0.0:4433".parse()?,
    cert_path: Some("cert.pem".to_string()),
    key_path: Some("key.pem".to_string()),
};

let transport = QuicAgentTransport::new(config);
```

### BLE Transport

```rust
use vigilnet_agent_transport::BleAgentTransport;

let transport = BleAgentTransport::new();
```

## Transport Trait

All transports implement the `AgentTransport` trait:

```rust
#[async_trait]
pub trait AgentTransport: Send + Sync {
    /// Bind to local address and start listening
    async fn bind(&mut self) -> TransportResult<()>;
    
    /// Connect to remote peer
    async fn connect(&self, addr: SocketAddr) 
        -> TransportResult<Box<dyn AgentConnection>>;
    
    /// Accept incoming connection
    async fn accept(&self) -> TransportResult<Box<dyn AgentConnection>>;
    
    /// Shutdown transport
    async fn shutdown(&mut self) -> TransportResult<()>;
    
    /// Get transport kind
    fn transport_kind(&self) -> TransportKind;
    
    /// Get local address
    fn local_addr(&self) -> TransportResult<SocketAddr>;
}
```

## Connection Trait

Connections implement `AgentConnection`:

```rust
#[async_trait]
pub trait AgentConnection: Send + Sync {
    /// Send data
    async fn send(&self, data: Bytes) -> TransportResult<()>;
    
    /// Receive data
    async fn recv(&self) -> TransportResult<Bytes>;
    
    /// Get remote address
    fn remote_addr(&self) -> SocketAddr;
    
    /// Get transport kind
    fn transport_kind(&self) -> TransportKind;
    
    /// Close connection
    async fn close(&self) -> TransportResult<()>;
}
```

## Unified Transport

Combine multiple transports:

```rust
use vigilnet_agent_transport::UnifiedTransport;

let unified = UnifiedTransport::new()
    .with_tcp(tcp_transport)
    .with_quic(quic_transport)
    .with_ble(ble_transport);

// Automatically selects best transport
let conn = unified.connect(addr).await?;
```

## Configuration

```rust
use vigilnet_agent_transport::TransportConfig;

let config = TransportConfig {
    max_connections: 256,
    connection_timeout_ms: 30_000,
    read_buffer_size: 64 * 1024,
    write_buffer_size: 64 * 1024,
    keepalive_interval_ms: 30_000,
    max_message_size: 10 * 1024 * 1024,
};
```

## Transport Kinds

```rust
pub enum TransportKind {
    Tcp,
    Quic,
    Ble,
    Tor,
    I2p,
    WireGuard,
    Mesh,
}
```

## Error Handling

```rust
pub enum TransportError {
    ConnectionFailed(String),
    NotAvailable(String),
    Io(std::io::Error),
    Serialization(serde_json::Error),
    Timeout(String),
    PeerNotFound(String),
    Session(String),
    Buffer(String),
    AuthFailed(String),
    RateLimited(String),
}
```

## Platform Support

| Transport | Linux | macOS | Windows | Android | iOS |
|-----------|-------|-------|---------|---------|-----|
| TCP | ✓ | ✓ | ✓ | ✓ | ✓ |
| QUIC | ✓ | ✓ | ✓ | ✓ | ✓ |
| BLE | ✓ | ✓ | ✗ | ✓ | ✓ |

## Integration

- `vigilnet-agent-core`: Agent network
- `vigilnet-tor`: Tor transport
- `vigilnet-i2p`: I2P transport
- `vigilnet-wireguard`: WireGuard transport
- `vigilnet-agent-mesh`: Mesh network

## License

GPL-3.0
