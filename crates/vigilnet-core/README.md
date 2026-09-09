# VigilNet Core

Core orchestration and node logic for the VigilNet privacy network.

## Overview

`vigilnet-core` is the main orchestration crate that coordinates all VigilNet subsystems. It provides:

- **Node Lifecycle Management**: Start, stop, and monitor VigilNet nodes
- **Configuration Management**: Load and save node configurations
- **Swarm Coordination**: Manage the libp2p swarm and peer connections
- **Circuit Building**: Create and manage anonymous circuits through the network
- **Agent Integration**: Optional integration with the agent network for E2EE communication

## Features

- `agent`: Enable agent network integration with Signal Protocol E2EE support

## Quick Start

```rust
use vigilnet_core::{Node, Config};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a node with default configuration
    let config = Config::default();
    let mut node = Node::new(config);
    
    // Start the node
    node.start().await?;
    
    // Get node information
    if let Some(peer_id) = node.local_peer_id().await {
        println!("Local peer ID: {}", peer_id);
    }
    
    // Build an anonymous circuit
    let circuit_id = node.build_circuit().await?;
    println!("Circuit {} built successfully", circuit_id);
    
    // Stop the node
    node.stop().await?;
    Ok(())
}
```

## Configuration

The node can be configured via TOML files:

```toml
[identity]
key_path = "~/.vigilnet/keys"
auto_generate = true

[network]
listen_addrs = ["/ip4/0.0.0.0/tcp/0"]
bootstrap_peers = []
enable_mdns = true
enable_dht = true

[privacy]
circuit_hops = 3
garlic_routing = false
dns_mode = "Local"
path_strategy = "Hybrid"

[tun]
enabled = false
device_name = "vigilnet0"
mtu = 1500

[relay]
enabled = false
smart_mode = true
bandwidth_limit = 0

[agent]
enabled = false
name = "vigilnet-node"
capabilities = ["proxy", "relay"]
model_type = "gpt-4"
enable_e2ee = true
pool_size = 32
```

## Key Components

### Node

The `Node` struct is the main entry point for running a VigilNet node. It manages:
- Connection to the peer-to-peer network
- Anonymous circuit building
- Traffic relaying
- Statistics tracking

### Config

The `Config` struct holds all node configuration options:
- Network settings (listen addresses, bootstrap peers)
- Privacy settings (circuit hops, path strategy)
- TUN interface configuration
- Relay configuration
- Agent network settings

### VigilNetSwarm

Internal swarm manager that:
- Manages the libp2p swarm
- Handles peer connections
- Routes circuit traffic
- Processes discovery events

## Privacy Features

- **Multi-hop Circuits**: Configurable number of hops (3-10) for anonymity
- **Path Strategies**: Random, lowest latency, hybrid, or reputation-weighted
- **Smart Relay Mode**: Automatically enables relaying for nodes with public IPs
- **Exit Policies**: Control what traffic can exit through your node

## Integration with Other Crates

- `vigilnet-crypto`: Encryption and key management
- `vigilnet-routing`: Circuit building and path selection
- `vigilnet-discovery`: Peer discovery (mDNS, DHT, gossip)
- `vigilnet-transport`: Network transport protocols
- `vigilnet-agent-core`: Optional agent network with E2EE (feature flag)

## Error Handling

All operations return `Result<T, Error>` where `Error` is a comprehensive error type covering:
- IO errors
- Configuration errors
- Network errors
- Crypto errors
- Agent errors
- Circuit errors

## License

GPL-3.0
