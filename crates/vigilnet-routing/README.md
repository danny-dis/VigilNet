# VigilNet Routing

Circuit building, path selection, and relay logic for the VigilNet privacy network.

## Overview

`vigilnet-routing` provides the core routing functionality:

- **Circuit Building**: Create multi-hop anonymous circuits
- **Path Selection**: Intelligent relay selection strategies
- **Relay Logic**: Handle circuit cells and forward traffic
- **Encrypted Circuits**: Signal Protocol E2EE for circuit traffic
- **Traffic Padding**: Protection against traffic analysis

## Quick Start

```rust
use vigilnet_routing::{CircuitBuilder, PathSelector, PathStrategy};

// Create a path selector with preferred strategy
let path_selector = PathSelector::new()
    .with_strategy(PathStrategy::Hybrid);

// Build circuits
let builder = CircuitBuilder::new(path_selector);
```

## Path Selection Strategies

### Random

Select relays randomly for maximum unpredictability:

```rust
use vigilnet_routing::PathStrategy;

let strategy = PathStrategy::Random;
```

### Low Latency

Prefer relays with lowest measured latency:

```rust
let strategy = PathStrategy::LowLatency;
```

### Hybrid (Default)

Balance between randomness and performance:

```rust
let strategy = PathStrategy::Hybrid;
```

### Reputation-Weighted

Prefer trusted, well-behaved relays:

```rust
let strategy = PathStrategy::ReputationWeighted;
```

## Circuit Building

### Basic Circuit

```rust
use vigilnet_routing::{CircuitBuilder, Circuit};

let builder = CircuitBuilder::new(path_selector);
let circuit = builder.build_circuit(3)?;  // 3-hop circuit

// Send data through circuit
circuit.send(data).await?;
```

### Encrypted Circuit (E2EE)

```rust
use vigilnet_routing::EncryptedCircuit;

let encrypted = EncryptedCircuit::new(circuit, session_key);
encrypted.send_encrypted(data).await?;
```

## Relay Operations

### Relay Logic

Relays process circuit cells and forward traffic:

```rust
use vigilnet_routing::{Relay, RelayCircuit};

let relay = Relay::new(my_peer_id_bytes);

// Handle CREATE cell
let (created_cell, session_key) = relay.handle_create(&create_cell, &static_secret)?;

// Store circuit state
let relay_circuit = RelayCircuit::new(circuit_id, peer_id, session_key);
```

### Cell Types

- `Create`: Initialize new circuit
- `Created`: Acknowledge circuit creation
- `Extend`: Add hop to existing circuit
- `Extended`: Acknowledge extension
- `Relay`: Encrypted data cell
- `Destroy`: Tear down circuit

## Exit Policies

Control what traffic can exit through your relay:

```rust
use vigilnet_routing::{ExitPolicy, PolicyAction};

let policy = ExitPolicy::default()
    .allow_port(80)    // HTTP
    .allow_port(443)   // HTTPS
    .deny_port(25);    // Block SMTP

match policy.check("example.com", 443) {
    PolicyAction::Allow => println!("Exit allowed"),
    PolicyAction::Deny => println!("Exit denied"),
}
```

## Traffic Padding

Protect against traffic analysis:

```rust
use vigilnet_routing::padding::PaddingStrategy;

let strategy = PaddingStrategy::Adaptive {
    min_padding: 100,
    max_padding: 1024,
    interval_ms: 1000,
};
```

## Circuit Management

### Circuit States

- `Pending`: Circuit being built
- `Established`: Ready for traffic
- `Destroyed`: Closed or failed

### Relay State

Track relay circuits:

```rust
use vigilnet_routing::RelayState;

let state = RelayState::new();
state.add_circuit(circuit_id, relay_circuit);
```

## Integration

Works with:
- `vigilnet-core`: Node-level circuit management
- `vigilnet-crypto`: Encryption and keys
- `vigilnet-discovery`: Relay discovery

## License

GPL-3.0
