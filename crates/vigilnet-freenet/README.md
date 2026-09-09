# VigilNet Freenet

Freenet decentralized storage integration for VigilNet.

## Overview

`vigilnet-freenet` provides integration with Freenet:

- **Content Hosting**: Store and retrieve content
- **Contracts**: Self-managing decentralized applications
- **Web Proxy**: Access Freenet content via HTTP
- **Node Operation**: Participate in the Freenet network

## Quick Start

```rust
use vigilnet_freenet::{FreenetClient, FreenetConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure client
    let config = FreenetConfig::default();
    
    // Create client
    let client = FreenetClient::new(config).await?;
    
    // Connect to network
    client.connect().await?;
    
    println!("Connected to Freenet");
    
    Ok(())
}
```

## Content Operations

### Put Content

```rust
use vigilnet_freenet::{ContentKey, ContentContract};

let data = b"Hello, Freenet!";
let key = client.put(data).await?;

println!("Content key: {}", key);
```

### Get Content

```rust
let content = client.get(&key).await?;
println!("Retrieved: {:?}", content);
```

### Update Content

```rust
let new_data = b"Updated content";
client.update(&key, new_data).await?;
```

## Contracts

### Deploy Contract

```rust
use vigilnet_freenet::Contract;

let contract = Contract::new()
    .with_code(contract_code)
    .with_state(initial_state);

let contract_id = client.deploy_contract(contract).await?;
```

### Call Contract

```rust
let result = client
    .call_contract(&contract_id, "get_value", vec![])
    .await?;
```

## Node Operations

### Run a Node

```rust
use vigilnet_freenet::FreenetNode;

let node = FreenetNode::new()
    .with_port(50509)
    .with_gateway_mode(true)
    .start()
    .await?;
```

### Gateway Configuration

```rust
let config = FreenetConfig {
    mode: NodeMode::Gateway,
    public_ip: Some("203.0.113.1".to_string()),
    public_port: 50509,
    bandwidth_limit: Some(1024 * 1024),  // 1 MB/s
};
```

## Web Integration

### HTTP Proxy

```rust
use vigilnet_freenet::WebProxy;

let proxy = WebProxy::new(client);
proxy.bind("127.0.0.1:8080").await?;

// Access Freenet via http://127.0.0.1:8080/USK@...
```

## Freenet URIs

### Key Types

- **CHK**: Content Hash Key (immutable)
- **SSK**: Signed Subspace Key (mutable)
- **USK**: Updateable Subspace Key (versioned)
- **KSK**: Keyword Signed Key (human-readable)

```rust
use vigilnet_freenet::FreenetKey;

// Parse Freenet URI
let key = FreenetKey::parse("USK@.../site/1/")?;

// Generate SSK
let (key, priv_key) = FreenetKey::generate_ssk();
```

## Configuration

```rust
use vigilnet_freenet::{FreenetConfig, NodeMode};

let config = FreenetConfig {
    mode: NodeMode::Client,
    port: 50509,
    peers: vec![
        "freenet://192.168.1.1:50509".to_string(),
    ],
    max_data_store_size: 1024 * 1024 * 1024,  // 1 GB
    bandwidth_limit: None,
};
```

## Error Handling

```rust
pub enum FreenetError {
    ConnectionFailed(String),
    ContentNotFound(String),
    ContractError(String),
    InvalidKey(String),
    Timeout,
}
```

## Integration

Used by:
- `vigilnet-core`: Decentralized storage backend
- `vigilnet-android`: Mobile Freenet access

## License

GPL-3.0
