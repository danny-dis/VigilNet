# VigilNet I2P

I2P network integration for VigilNet.

## Overview

`vigilnet-i2p` provides I2P (Invisible Internet Project) network integration:

- **SAM Bridge**: Connect to I2P via SAM 3.1 protocol
- **Tunnels**: Manage I2P tunnels for inbound/outbound connections
- **Eepsites**: Access I2P hidden services
- **Garlic Routing**: Multi-layer encryption through I2P
- **E2EE**: Signal Protocol on top of I2P

## Quick Start

```rust
use vigilnet_i2p::{SamClient, I2pTransport, SessionType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to SAM bridge
    let sam = SamClient::connect("127.0.0.1:7656").await?;
    
    // Create I2P transport
    let mut transport = I2pTransport::new(sam);
    
    // Create session
    transport.create_session(SessionType::Stream, "vigilnet").await?;
    
    println!("I2P Destination: {:?}", transport.destination());
    
    Ok(())
}
```

## SAM Client

### Connect to SAM Bridge

```rust
use vigilnet_i2p::SamClient;

// Connect to local I2P router
let mut client = SamClient::connect("127.0.0.1:7656").await?;

// Or use default
let mut client = SamClient::default().await?;
```

### Create Session

```rust
use vigilnet_i2p::SessionType;

// Create streaming session
let session_id = client
    .create_session(SessionType::Stream, "my-app")
    .await?;

// Get your I2P destination
let destination = client.destination();
```

### Stream Connections

```rust
// Connect to remote destination
let stream = client
    .stream_connect("some-destination.b32.i2p")
    .await?;

// Accept incoming connections
let stream = client.accept().await?;
```

## Tunnels

### Tunnel Pool

```rust
use vigilnet_i2p::{TunnelPool, TunnelConfig, TunnelDirection};

let pool = TunnelPool::new();

// Add inbound tunnel
pool.add_tunnel(TunnelConfig {
    direction: TunnelDirection::Inbound,
    length: 3,
    quantity: 2,
});

// Add outbound tunnel
pool.add_tunnel(TunnelConfig {
    direction: TunnelDirection::Outbound,
    length: 3,
    quantity: 2,
});
```

## Naming Service

Resolve I2P hostnames:

```rust
use vigilnet_i2p::NamingService;

let naming = NamingService::new();

// Lookup address
if let Some(dest) = naming.lookup("i2p-projekt.i2p") {
    println!("Destination: {}", dest);
}

// Add custom entry
naming.add("my-service.i2p", "destination-string");
```

## E2EE over I2P

```rust
use vigilnet_crypto::PreKeyBundle;

let mut transport = I2pTransport::new(sam);
transport.enable_e2ee(prekey_bundle)?;
```

## Transport Integration

```rust
use vigilnet_agent_transport::AgentTransport;

#[async_trait]
impl AgentTransport for I2pTransport {
    async fn bind(&mut self) -> TransportResult<()> {
        self.connect_sam().await?;
        self.create_session(SessionType::Stream, "vigilnet").await?;
        Ok(())
    }
    
    async fn connect(&self, addr: SocketAddr) -> TransportResult<Box<dyn AgentConnection>> {
        // Connect via I2P
    }
    
    // ... other methods
}
```

## Session Types

```rust
pub enum SessionType {
    Stream,  // TCP-like streaming
    Datagram, // UDP-like datagrams
    Raw,     // Raw datagrams
}
```

## Configuration

```rust
use vigilnet_i2p::{I2pConfig, SamConfig};

let config = I2pConfig {
    sam_host: "127.0.0.1".to_string(),
    sam_port: 7656,
    session_timeout_secs: 300,
};
```

## Error Handling

```rust
pub enum I2pError {
    SamConnectionFailed(String),
    TunnelFailed(String),
    DestinationNotFound(String),
    NamingError(String),
    ConnectionFailed(String),
    E2eeError(String),
}
```

## Comparison with Tor

| Feature | I2P | Tor |
|---------|-----|-----|
| Direction | P2P-focused | Client-server |
| Hidden Services | Built-in | Onion services |
| Routing | Garlic routing | Onion routing |
| Latency | Higher | Lower |
| Throughput | Lower | Higher |
| Use Case | Internal services | External access |

## Integration

Used by:
- `vigilnet-core`: As a routing backend
- `vigilnet-agent-transport`: Agent network transport

## License

GPL-3.0
