# VigilNet CLI

Command-line interface for VigilNet.

## Overview

`vigilnet-cli` provides a command-line interface for managing VigilNet nodes:

- **Node Management**: Start, stop, and monitor nodes
- **Configuration**: Edit and view settings
- **Agent Operations**: Manage agent network
- **Circles**: Private group communication
- **Research**: Multi-perspective analysis

## Installation

```bash
# Build from source
cargo build --release -p vigilnet-cli

# Install
cargo install --path crates/vigilnet-cli

# Or with cargo-binstall
cargo binstall vigilnet-cli
```

## Quick Start

```bash
# Initialize configuration
vigilnet init

# Start interactive node
vigilnet run

# Check status
vigilnet status

# List connected peers
vigilnet peers
```

## Commands

### Node Management

```bash
# Start node in foreground
vigilnet start --foreground

# Start in background (daemon)
vigilnet start

# Stop node
vigilnet stop

# Check status
vigilnet status

# View configuration
vigilnet config

# View as JSON
vigilnet config --json
```

### Run Mode

Interactive test node with web UI:

```bash
$ vigilnet run

╔═══════════════════════════════════════════╗
║         VigilNet Test Node Running        ║
╠═══════════════════════════════════════════╣
║ Peer ID: 12D3KooW...                      ║
║ SOCKS5:  127.0.0.1:9050 (E2EE)            ║
║ Web UI:  http://127.0.0.1:9051           ║
╚═══════════════════════════════════════════╝

Listening for peers via mDNS and DHT...
Press Ctrl+C to stop.

Status: 5 peers, 2 circuits, 120s uptime
  - 12D3KooWABC...
  - 12D3KooWDEF...
  ...
```

### Agent Network

```bash
# Start an agent
vigilnet agent start --name "my-agent" --capabilities finance,security

# List agents
vigilnet agent list

# Send encrypted message
vigilnet agent send --to "agent-id" --message "Hello"

# View agent info
vigilnet agent info
```

### Circles

Private encrypted groups:

```bash
# Create a circle
vigilnet circle create "Friends" --circle-type private

# Join a circle
vigilnet circle join "vigilnet://circle/uuid"

# List circles
vigilnet circle list

# Send message to circle
vigilnet circle send --name "Friends" --message "Hello everyone!"

# Leave circle
vigilnet circle leave "Friends"
```

### Research

Multi-perspective analysis:

```bash
$ vigilnet research "blockchain technology"

Running multi-perspective research...
Query: blockchain technology

[Finance Perspective]
  - Market analysis: $XXX
  - Risk assessment: Medium
  - Recommendations: Buy, Hold, Sell

[Technology Perspective]
  - Technical feasibility: High
  - Innovation score: 8/10
  - Implementation complexity: Medium

[Legal Perspective]
  - Compliance status: Pending review
  - Regulatory concerns: None identified
  - Recommendations: Consult counsel

[Security Perspective]
  - Threat model: To be determined
  - Security score: 7/10
  - Recommendations: Implement encryption

Summary: Multi-perspective analysis complete.
         4 perspectives analyzed.
```

## Global Options

```bash
# Verbose logging
vigilnet --verbose run

# Custom config path
vigilnet --config /path/to/config.toml start
```

## Configuration File

```toml
# ~/.vigilnet/config.toml

[identity]
key_path = "~/.vigilnet/keys"

[network]
listen_addrs = ["/ip4/0.0.0.0/tcp/0"]
enable_mdns = true
enable_dht = true

[privacy]
circuit_hops = 3
path_strategy = "Hybrid"

[agent]
enabled = true
name = "cli-agent"
capabilities = ["proxy", "relay"]
```

## Web UI

When running `vigilnet run`, a web UI is available at http://127.0.0.1:9051:

- Node status and statistics
- Peer list
- Circuit visualization
- Agent management
- Circle management

## SOCKS5 Proxy

The CLI provides a SOCKS5 proxy for routing traffic:

```bash
# Configure applications to use SOCKS5 at 127.0.0.1:9050
curl --socks5 127.0.0.1:9050 https://example.com
```

## Troubleshooting

```bash
# Check logs
vigilnet --verbose run

# Verify configuration
vigilnet config

# Regenerate identity
vigilnet init --force
```

## Shell Completions

```bash
# Bash
vigilnet completions bash > /etc/bash_completion.d/vigilnet

# Zsh
vigilnet completions zsh > /usr/local/share/zsh/site-functions/_vigilnet

# Fish
vigilnet completions fish > ~/.config/fish/completions/vigilnet.fish
```

## Integration

- `vigilnet-core`: Node operations
- `vigilnet-proxy`: SOCKS5 proxy
- `vigilnet-agent-core`: Agent management
- `vigilnet-agent-circles`: Circle operations
- `vigilnet-agent-research`: Research functionality

## License

GPL-3.0
