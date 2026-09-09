# VigilNet Proxy

SOCKS5 proxy server for VigilNet with Signal Protocol E2EE support.

## Overview

`vigilnet-proxy` provides a SOCKS5 proxy that routes traffic through the VigilNet privacy network:

- **SOCKS5 Protocol**: Standard SOCKS5 proxy support
- **E2EE Encryption**: Signal Protocol encryption between client and exit node
- **Circuit Routing**: Anonymous multi-hop circuits for all traffic
- **Transparent Proxying**: Works with any SOCKS5-compatible application

## Quick Start

```rust
use vigilnet_proxy::SocksProxy;
use std::sync::Arc;
use vigilnet_core::Node;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Start VigilNet node
    let config = vigilnet_core::Config::default();
    let mut node = Node::new(config);
    node.start().await?;
    
    // Create SOCKS5 proxy
    let proxy_addr = "127.0.0.1:9050".parse()?;
    let proxy = SocksProxy::new(proxy_addr, Arc::new(node));
    
    // Run proxy
    proxy.run().await?;
    
    Ok(())
}
```

## Configuration

### Basic Proxy

```rust
use vigilnet_proxy::SocksProxy;

let proxy = SocksProxy::new(proxy_addr, node);
proxy.run().await?;
```

### With E2EE

```rust
use vigilnet_proxy::SocksProxy;

let proxy = SocksProxy::new(proxy_addr, node)
    .enable_e2ee();
    
proxy.run().await?;
```

## Usage

### Configure Applications

Once the proxy is running, configure applications to use SOCKS5:

```bash
# curl
curl --socks5 127.0.0.1:9050 https://example.com

# Firefox
# Settings -> Network Settings -> Manual proxy configuration
# SOCKS Host: 127.0.0.1, Port: 9050

# Chrome (with extension)
# Use SwitchyOmega or similar

# Git
git config --global http.proxy socks5://127.0.0.1:9050
```

### Environment Variables

```bash
export ALL_PROXY=socks5://127.0.0.1:9050
export HTTP_PROXY=socks5://127.0.0.1:9050
export HTTPS_PROXY=socks5://127.0.0.1:9050
```

## SOCKS5 Features

- **No Authentication**: Anonymous access (default)
- **Username/Password**: Optional authentication
- **IPv4/IPv6**: Full address family support
- **Domain Names**: Resolve through VigilNet DNS
- **UDP Associate**: UDP relay (if supported by exit node)
- **BIND**: Incoming connections (limited support)

## E2EE Mode

When E2EE is enabled, all traffic between your client and the exit node is encrypted with the Signal Protocol:

1. **X3DH Key Agreement**: Establish shared secret
2. **Double Ratchet**: Forward-secure message encryption
3. **Per-Connection Sessions**: Unique encryption per TCP stream

```rust
// Enable E2EE on proxy
let proxy = SocksProxy::new(proxy_addr, node)
    .enable_e2ee();
```

## Security Considerations

- **Local Binding**: By default binds to localhost only
- **No Remote Access**: Prevents unauthorized proxy usage
- **Circuit Isolation**: Each connection uses separate circuit
- **DNS Protection**: DNS queries routed through VigilNet

## Performance

- **Connection Pooling**: Reuse circuits for multiple connections
- **Async I/O**: Tokio-based for high concurrency
- **Zero-Copy**: Minimize data copying where possible

## Error Handling

Comprehensive error types:

```rust
pub enum ProxyError {
    Io(std::io::Error),
    InvalidVersion(u8),
    InvalidMethod(u8),
    AuthFailed(String),
    ConnectionFailed(String),
    CircuitError(String),
}
```

## Integration

Used by:
- `vigilnet-cli`: Command-line proxy
- `vigilnet-android`: Android VPN proxy

## License

GPL-3.0
