# VigilNet Discovery

Peer discovery mechanisms for the VigilNet privacy network.

## Overview

`vigilnet-discovery` provides multiple peer discovery mechanisms:

- **Kademlia DHT**: Global peer discovery with caching and prefetch
- **mDNS**: Local network peer discovery
- **Gossip Protocol**: Overlay state propagation
- **Sybil Defense**: Protection against malicious peers via Proof of Work

## Quick Start

```rust
use vigilnet_discovery::{CombinedDiscovery, DhtDiscovery, MdnsDiscovery};

// Create combined discovery with DHT and mDNS
let mut discovery = CombinedDiscovery::new()
    .with_dht(DhtDiscovery::new()?)
    .with_mdns(MdnsDiscovery::new()?);

// Start all discovery mechanisms
discovery.start_all()?;

// Get all discovered peers
let peers = discovery.all_peers();
println!("Discovered {} peers", peers.len());

// Stop discovery
discovery.stop_all()?;
```

## Discovery Mechanisms

### Kademlia DHT

Global distributed hash table for peer discovery:

```rust
use vigilnet_discovery::DhtDiscovery;

let mut dht = DhtDiscovery::new()
    .with_bootstrap_nodes(vec![
        "/dns4/bootstrap1.vigilnet.local/tcp/4001",
    ]);

dht.start()?;

// Peers are automatically discovered and added
let peers = dht.known_peers();
```

### mDNS

Multicast DNS for local network discovery:

```rust
use vigilnet_discovery::MdnsDiscovery;

let mut mdns = MdnsDiscovery::new()?;
mdns.start()?;

// Automatically discovers peers on the same LAN
```

### Gossip Protocol

Propagates peer information through the network:

```rust
use vigilnet_discovery::GossipProtocol;

let mut gossip = GossipProtocol::new();
gossip.start()?;

// Subscribe to topics
gossip.subscribe("peer-updates");
```

## Sybil Defense

Protection against Sybil attacks via Proof of Work:

```rust
use vigilnet_discovery::sybil_defense::{SybilDefense, PowConfig};

let config = PowConfig {
    difficulty: 4,  // Number of leading zero bits required
    max_age_secs: 3600,
};

let defense = SybilDefense::new(config);

// Verify peer's PoW commitment
if defense.verify_commitment(&peer_id, &commitment)? {
    // Peer is verified, add to routing table
}
```

## Combined Behavior

The `VigilNetBehaviour` combines all discovery mechanisms into a single libp2p behavior:

```rust
use vigilnet_discovery::VigilNetBehaviour;
use libp2p::PeerId;

let behaviour = VigilNetBehaviour::new(local_peer_id, &keypair);

// The behavior handles:
// - Kademlia routing
// - mDNS discovery
// - GossipSub messaging
// - Identify protocol
// - Circuit relay protocol
// - E2EE session management
```

## Events

Listen for discovery events:

```rust
use vigilnet_discovery::DiscoveryEvent;

match event {
    DiscoveryEvent::PeerDiscovered(peer_id) => {
        println!("New peer: {}", peer_id);
    }
    DiscoveryEvent::PeerLost(peer_id) => {
        println!("Peer lost: {}", peer_id);
    }
    DiscoveryEvent::VerifiedPeer(peer_id) => {
        println!("Peer verified: {}", peer_id);
    }
}
```

## Features

- Multi-mechanism discovery (DHT, mDNS, gossip)
- Automatic peer verification
- Caching and prefetching for performance
- Sybil attack resistance
- E2EE session management integration

## Integration

Works seamlessly with:
- `vigilnet-core`: Node orchestration
- `vigilnet-routing`: Circuit building
- `vigilnet-crypto`: E2EE sessions

## License

GPL-3.0
