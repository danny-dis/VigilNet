# VigilNet Tor

Tor network integration for VigilNet.

## Overview

`vigilnet-tor` provides Tor network integration via the Arti library:

- **Tor Client**: Connect to the Tor network
- **Onion Services**: Host hidden services
- **Bridge Support**: Use bridges for censorship resistance
- **E2EE**: Signal Protocol encryption on top of Tor

## Quick Start

```rust
use vigilnet_tor::{TorClient, TorTransport};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create Tor client
    let client = TorClient::new();
    
    // Create transport
    let transport = TorTransport::new(client);
    
    // Bind and start
    transport.bind().await?;
    
    Ok(())
}
```

## Tor Client

### Basic Usage

```rust
use vigilnet_tor::{TorClient, TorState};

let mut client = TorClient::new();
client.start().await?;

// Wait for bootstrap
while client.state() != TorState::Connected {
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
}

// Connect through Tor
let stream = client.connect("example.com", 443).await?;
```

### Isolation Policy

```rust
use vigilnet_tor::IsolationPolicy;

let policy = IsolationPolicy::new()
    .isolate_by_destination()
    .isolate_by_credentials();

let client = TorClient::new().with_policy(policy);
```

## Bridges

Connect via bridges for censorship resistance:

```rust
use vigilnet_tor::{BridgeConfig, TransportType};

let bridge = BridgeConfig::new()
    .with_transport(TransportType::Obfs4)
    .with_address("192.95.36.142:443")
    .with_fingerprint("...");

let client = TorClient::new()
    .with_bridge(bridge);
```

## Onion Services

### Create Hidden Service

```rust
use vigilnet_tor::OnionServiceManager;

let manager = OnionServiceManager::new();

let service = manager
    .create_service(8080, 80)  // local_port, virtual_port
    .await?;

println!("Onion address: {}", service.address());
```

### Connect to Onion Service

```rust
let stream = client
    .connect_onion("abcdefghijklmnop.onion", 80)
    .await?;
```

## E2EE over Tor

Add Signal Protocol encryption on top of Tor:

```rust
use vigilnet_crypto::PreKeyBundle;

let mut transport = TorTransport::new(client);
transport.enable_e2ee(prekey_bundle)?;
```

## Transport Integration

Implements `AgentTransport` trait:

```rust
use vigilnet_agent_transport::AgentTransport;

#[async_trait]
impl AgentTransport for TorTransport {
    async fn bind(&mut self) -> TransportResult<()> {
        // Start Tor client
    }
    
    async fn connect(&self, addr: SocketAddr) -> TransportResult<Box<dyn AgentConnection>> {
        // Connect via Tor
    }
    
    // ... other methods
}
```

## Configuration

```rust
use vigilnet_tor::{TorConfig, TorState};

let config = TorConfig {
    socks_port: 9050,
    control_port: Some(9051),
    bridges: vec![],
    use_bridges: false,
    isolation_policy: IsolationPolicy::default(),
};

let client = TorClient::with_config(config);
```

## States

```rust
pub enum TorState {
    Created,      // Client created, not started
    Bootstrapping, // Connecting to Tor network
    Connected,    // Ready to use
    Error(String), // Error state
}
```

## Error Handling

```rust
pub enum TorError {
    NotInitialized,
    BootstrapFailed(String),
    CircuitFailed(String),
    BridgeError(String),
    OnionServiceError(String),
    ConnectionFailed(String),
    E2eeError(String),
}
```

## Security Notes

- Tor provides transport-layer anonymity
- VigilNet adds application-layer E2EE
- Combined for defense in depth
- Circuit isolation per connection

## Integration

Used by:
- `vigilnet-core`: As a routing backend
- `vigilnet-android`: Mobile Tor support
- `vigilnet-agent-transport`: Agent network transport

## License

GPL-3.0
