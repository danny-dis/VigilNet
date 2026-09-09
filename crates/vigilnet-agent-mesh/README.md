# VigilNet Agent Mesh

Offline mesh networking for VigilNet agents.

## Overview

`vigilnet-agent-mesh` provides communication when internet connectivity is unavailable:

- **BLE Mesh**: Bluetooth Low Energy mesh networking
- **Meshtastic Bridge**: Integration with Meshtastic devices
- **DTN Store**: Delay-tolerant networking message storage
- **Mesh Fallback**: Automatic fallback to mesh networks

## Quick Start

```rust
use vigilnet_agent_mesh::{MeshNetwork, MeshConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = MeshConfig::default();
    let mesh = MeshNetwork::new(config);
    
    // Start mesh networking
    mesh.start().await?;
    
    // Send message via mesh
    mesh.broadcast(b"Hello, mesh!").await?;
    
    Ok(())
}
```

## BLE Mesh

### Enable BLE

```rust
use vigilnet_agent_mesh::BleMesh;

let ble = BleMesh::new();
ble.enable().await?;
```

### Discover Peers

```rust
let peers = ble.discover_peers().await?;
for peer in peers {
    println!("Found: {}", peer.id);
}
```

### Send Message

```rust
ble.send_to(&peer_id, b"Hello!").await?;
```

## Meshtastic Bridge

Connect to Meshtastic LoRa devices:

```rust
use vigilnet_agent_mesh::MeshtasticBridge;

let bridge = MeshtasticBridge::new("/dev/ttyUSB0");
bridge.connect().await?;

// Messages automatically bridged between VigilNet and Meshtastic
```

## DTN Store

Delay-tolerant networking for intermittent connectivity:

```rust
use vigilnet_agent_mesh::DtnStore;

let store = DtnStore::new();

// Store message for later delivery
store.enqueue(message, recipient).await?;

// Process when connectivity available
store.flush().await?;
```

## Mesh Fallback

Automatic fallback to mesh when internet unavailable:

```rust
use vigilnet_agent_mesh::MeshFallback;

let fallback = MeshFallback::new()
    .with_ble(ble_mesh)
    .with_dtn(dtn_store);

// Automatically routes via mesh when needed
```

## Configuration

```rust
use vigilnet_agent_mesh::MeshConfig;

let config = MeshConfig {
    ble_enabled: true,
    meshtastic_enabled: false,
    wifi_direct_enabled: true,
    dtn_enabled: true,
    max_hops: 5,
    ttl_seconds: 3600,
};
```

## Network Topologies

- **Star**: Central coordinator
- **Mesh**: Peer-to-peer routing
- **Hybrid**: Combined infrastructure

## Range

- **BLE**: ~100m (line of sight)
- **Wi-Fi Direct**: ~200m
- **Meshtastic/LoRa**: Several km

## Use Cases

- Emergency communication
- Offline messaging
- Rural connectivity
- Disaster response
- Protest coordination

## Integration

- `vigilnet-agent-core`: Agent network
- `vigilnet-agent-transport`: Transport layer
- `vigilnet-android`: Mobile mesh

## License

GPL-3.0
