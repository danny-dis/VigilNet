# VigilNet Nym

Nym mixnet integration for VigilNet.

## Overview

`vigilnet-nym` provides integration with the Nym privacy network:

- **Mixnet Routing**: Multi-hop mixnet for metadata privacy
- **Sphinx Packets**: Unlinkable packet format
- **Cover Traffic**: Protection against traffic analysis
- **High Latency**: Privacy over performance

## Quick Start

```rust
use vigilnet_nym::{NymClient, NymTransport};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create Nym client
    let client = NymClient::new();
    
    // Connect to mixnet
    client.connect().await?;
    
    // Create transport
    let transport = NymTransport::new(client);
    
    Ok(())
}
```

## Nym Client

### Basic Usage

```rust
use vigilnet_nym::NymClient;

let client = NymClient::new()
    .with_gateway("gateway1.nymtech.net")
    .connect()
    .await?;

// Send message through mixnet
client.send("recipient-address", b"Hello, Nym!").await?;

// Receive messages
while let Some(msg) = client.receive().await {
    println!("Received: {:?}", msg);
}
```

### Mixnet Configuration

```rust
use vigilnet_nym::MixnetConfig;

let config = MixnetConfig {
    num_mix_hops: 3,
    average_packet_delay_ms: 50,
    average_ack_delay_ms: 50,
    loop_cover_traffic_average_delay_ms: 1000,
    message_sending_average_delay_ms: 100,
    gateway_response_timeout_ms: 1000,
};

let client = NymClient::with_config(config);
```

## Transport Integration

```rust
use vigilnet_agent_transport::AgentTransport;

#[async_trait]
impl AgentTransport for NymTransport {
    async fn bind(&mut self) -> TransportResult<()> {
        self.client.connect().await
            .map_err(|e| TransportError::Bind(e.to_string()))
    }
    
    async fn connect(&self, addr: SocketAddr) -> TransportResult<Box<dyn AgentConnection>> {
        // Connect via Nym mixnet
    }
    
    // ... other methods
}
```

## When to Use Nym

### Best For

- **High-Security Messages**: When metadata privacy is critical
- **Whistleblowing**: Maximum anonymity required
- **Journalism**: Protect sources
- **Dissidents**: Avoid network surveillance

### Trade-offs

- **Higher Latency**: 100-500ms additional delay
- **Lower Throughput**: Mixnet overhead
- **Cover Traffic**: Bandwidth overhead

## Comparison

| Network | Latency | Metadata Privacy | Throughput | Use Case |
|---------|---------|------------------|------------|----------|
| Tor | Low | Medium | High | General browsing |
| I2P | Medium | High | Medium | P2P services |
| Nym | High | Very High | Low | High-security |
| WireGuard | Very Low | None | Very High | Fast VPN |

## Configuration

```rust
use vigilnet_nym::NymConfig;

let config = NymConfig {
    client_id: "my-client".to_string(),
    gateway: None,  // Auto-select
    validators: vec![
        "https://validator1.nymtech.net",
        "https://validator2.nymtech.net",
    ],
    disable_cover_traffic: false,
    traffic_rate: TrafficRate::Normal,
};
```

## Error Handling

```rust
pub enum NymError {
    ConnectionFailed(String),
    GatewayError(String),
    MixnetError(String),
    InvalidAddress(String),
    Timeout,
}
```

## Integration

Used by:
- `vigilnet-core`: As a routing backend option
- `vigilnet-agent-transport`: Agent network transport

## License

GPL-3.0
