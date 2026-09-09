# VigilNet Agent Core

Core components for the VigilNet agent network.

## Overview

`vigilnet-agent-core` provides the foundation for the agent network:

- **Agent Identity**: Unique identification and metadata
- **Connection Pooling**: High-speed QUIC connection management
- **Message Protocol**: Binary serialization for efficiency
- **Registry**: Agent discovery and lookup
- **E2EE**: Signal Protocol encryption

## Quick Start

```rust
use vigilnet_agent_core::{Agent, AgentBuilder, AgentId};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build an agent
    let agent = AgentBuilder::new()
        .name("my-agent")
        .capabilities(vec!["finance".to_string(), "security".to_string()])
        .model_type("gpt-4")
        .enable_e2ee()
        .build()
        .await?;
    
    println!("Agent ID: {}", agent.id());
    println!("Capabilities: {:?}", agent.info().capabilities);
    
    Ok(())
}
```

## Agent

### Basic Agent

```rust
use vigilnet_agent_core::Agent;

let agent = Agent::new(
    "finance-agent".to_string(),
    vec!["finance".to_string(), "analysis".to_string()],
    "gpt-4".to_string(),
)?;
```

### Agent Information

```rust
let info = agent.info();
println!("Name: {}", info.name);
println!("Model: {}", info.model_type);
println!("Online: {}", info.is_online);
println!("Trust: {}", info.trust_score);
```

### Update Status

```rust
agent.set_online(true);
agent.update_latency(100_000_000);  // 100ms in nanoseconds
agent.update_trust_score(0.1);  // Increase trust
```

## Builder Pattern

```rust
use vigilnet_agent_core::AgentBuilder;
use vigilnet_agent_core::ConnectionPoolConfig;

let config = ConnectionPoolConfig {
    max_connections: 32,
    connect_timeout: Duration::from_secs(10),
    idle_timeout: Duration::from_secs(300),
};

let agent = AgentBuilder::new()
    .name("research-agent")
    .capabilities(vec!["research".to_string(), "analysis".to_string()])
    .model_type("claude-3")
    .connection_pool_config(config)
    .enable_e2ee()
    .build()
    .await?;
```

## Connection Pool

### Configuration

```rust
use vigilnet_agent_core::ConnectionPoolConfig;

let config = ConnectionPoolConfig {
    max_connections: 32,
    connect_timeout: Duration::from_secs(10),
    idle_timeout: Duration::from_secs(300),
};
```

### Usage

```rust
if let Some(pool) = agent.connection_pool() {
    // Check for existing session
    if pool.has_session(&peer_id) {
        // Send encrypted message
        let msg = agent.send_encrypted(&peer_id, payload)?;
    }
}
```

## E2EE (Signal Protocol)

### Initialize

```rust
// E2EE is initialized automatically with .enable_e2ee() in builder
agent.initialize_e2ee();
```

### Get PreKey Bundle

```rust
if let Some(bundle) = agent.get_prekey_bundle() {
    // Share this bundle with peers to receive encrypted messages
    println!("Identity Key: {:?}", bundle.identity_key);
}
```

### Create Session

```rust
// Create E2EE session with peer
agent.create_session(&peer_id, &their_prekey_bundle)?;
```

### Send/Receive Encrypted

```rust
// Send
let encrypted = agent.send_encrypted(&peer_id, b"Secret message")?;

// Receive
let decrypted = agent.receive_encrypted(&peer_id, &encrypted)?;
```

## Registry

### Agent Registry

```rust
use vigilnet_agent_core::AgentRegistry;

let registry = AgentRegistry::new()
    .with_local_agent(agent_info);

// Register remote agent
registry.register(remote_agent_info)?;

// Lookup agent
if let Some(agent) = registry.lookup(&agent_id) {
    println!("Found: {}", agent.name);
}
```

## Messages

### Message Types

```rust
use vigilnet_agent_core::MessageType;

match message_type {
    MessageType::Handshake => { /* Handle handshake */ }
    MessageType::Data => { /* Handle data */ }
    MessageType::Heartbeat => { /* Handle heartbeat */ }
    MessageType::Encrypted(_) => { /* Handle encrypted */ }
}
```

### Serialization

```rust
use vigilnet_agent_core::MessageSerializer;

let message = Message::new(MessageType::Data, payload);
let bytes = MessageSerializer::serialize(&message)?;
let restored = MessageSerializer::deserialize(&bytes)?;
```

## Agent ID

```rust
use vigilnet_agent_core::AgentId;
use libp2p::PeerId;

// Create from PeerId
let peer_id = PeerId::random();
let agent_id = AgentId::new(peer_id);

// Convert to/from string
let id_string = agent_id.to_string();
let agent_id = AgentId::parse(&id_string)?;
```

## Integration

- `vigilnet-crypto`: Signal Protocol E2EE
- `vigilnet-discovery`: Peer discovery
- `vigilnet-agent-transport`: Network transports
- `vigilnet-agent-circles`: Private groups
- `vigilnet-agent-research`: Multi-perspective research

## License

GPL-3.0
