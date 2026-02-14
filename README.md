# VigilNet

A privacy-first P2P tunneling network with onion routing, system-wide VPN functionality, and offline mesh fallback.

## Features

- 🧅 **Onion Routing** - Multi-hop encrypted circuits (3-10 hops)
- 🌐 **Decentralized** - No central servers, fully P2P mesh
- 🔐 **End-to-End Encryption** - AES-GCM with ephemeral X25519 keys
- 📡 **Multiple Discovery** - DHT, mDNS, and gossip protocols
- 🖧 **System VPN** - TUN interface for all IP traffic
- 📴 **Offline Fallback** - BLE/Wi-Fi mesh when Internet fails
- 🔒 **Privacy Circles** - Private overlay networks via shared secrets

## Why VigilNet?

### For Normal Users
- **Invisible Browsing**: Your traffic is encrypted and bounces through 3 random nodes. Websites can't see your IP, and your ISP can't see your destination.
- **Unblock Content**: Access geo-restricted or blocked websites by routing through nodes in other countries.
- **No Trust Required**: Unlike VPNs, there is no central company that can sell your data. The network is run by people like you.

### For Power Users
- **SOCKS5 Interface**: Use VigilNet with *any* application that supports SOCKS proxies (`curl`, `ssh`, `git`, browsers, etc.) via `127.0.0.1:9050`.
- **Run a Relay**: Contribute bandwidth to the network by running a relay node. Help freedom of information worldwide.
- **Verification**: The code is 100% open source. You can audit the cryptography and build from source.
- **Resilience**: The decentralized P2P architecture means the network cannot be taken down by shutting off a single server.

## Architecture

```
vigilnet/
├── vigilnet-core/       # Node orchestration
├── vigilnet-crypto/     # Onion encryption, keys
├── vigilnet-routing/    # Circuit building
├── vigilnet-discovery/  # DHT, mDNS, gossip
├── vigilnet-transport/  # TCP, QUIC, BLE
├── vigilnet-tun/        # VPN interface
└── vigilnet-cli/        # Command-line interface
```

## Building

```bash
# Install Rust (if not already)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build all crates
cargo build --workspace

# Run tests
cargo test --workspace

# Run CLI
cargo run -p vigilnet-cli -- --help
```

## Usage

```bash
# Start a node (Web UI at http://localhost:9051)
vigilnet start

# Use SOCKS5 Proxy
curl --proxy socks5://127.0.0.1:9050 https://check.torproject.org/api/ip

# Join a private circle
vigilnet circle join <token>
```

## Requirements

- Rust 1.75+
- Linux, Windows, or macOS
- Administrator/root privileges (for TUN interface)

## License

GPL-3.0
