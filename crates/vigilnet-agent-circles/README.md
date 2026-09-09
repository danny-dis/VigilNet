# VigilNet Agent Circles

Private encrypted group communication for VigilNet agents.

## Overview

`vigilnet-agent-circles` provides secure, private group communication:

- **Circle Creation**: Create private or audit groups
- **Invite System**: Token-based circle membership
- **Group Encryption**: Shared symmetric keys for group messages
- **Member Management**: Add/remove members securely

## Quick Start

```rust
use vigilnet_agent_circles::{CirclesService, CircleType};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let circles = CirclesService::new();
    
    // Create a private circle
    let creator_id = Uuid::new_v4();
    let creator_key = [0x42u8; 32];
    
    let circle_id = circles
        .create_circle("Friends".to_string(), CircleType::Private, creator_id, creator_key, 10)
        .await?;
    
    println!("Created circle: {}", circle_id);
    
    Ok(())
}
```

## Circle Types

### Private

End-to-end encrypted group:

```rust
use vigilnet_agent_circles::CircleType;

let circle_type = CircleType::Private;
```

### Audit

Publicly auditable group:

```rust
let circle_type = CircleType::Audit;
```

## Creating Circles

```rust
use vigilnet_agent_circles::CirclesService;
use uuid::Uuid;

let circles = CirclesService::new();

let circle_id = circles.create_circle(
    "My Circle".to_string(),
    CircleType::Private,
    creator_id,
    creator_key,
    50,  // max members
).await?;
```

## Joining Circles

### Via Token

```rust
// Creator generates invite token
let circle = circles.get_circle(circle_id).await?;
let token = circle.generate_invite_token();

// Member joins using token
circles.join_circle(token).await?;
```

### Via Direct Invite

```rust
circles.invite_member(circle_id, member_id).await?;
```

## Sending Messages

### Encrypt for Circle

```rust
let message = b"Hello, circle!";
let encrypted = circles
    .encrypt_for_circle(circle_id, message)
    .await?;
```

### Decrypt Message

```rust
let decrypted = circles
    .decrypt_from_circle(circle_id, &encrypted)
    .await?;
```

## Member Management

```rust
// Add member
circles.add_member(circle_id, member_id, member_key).await?;

// Remove member
circles.remove_member(circle_id, member_id).await?;

// List members
let members = circles.list_members(circle_id).await?;
```

## Security Features

- **Symmetric Encryption**: AES-256-GCM for group messages
- **Key Rotation**: Automatic key rotation when members change
- **Forward Secrecy**: Keys derived from member key agreement
- **Access Control**: Only circle members can decrypt messages

## Circle Lifecycle

```
Create → Invite → Join → Communicate → Leave → Destroy
```

## Configuration

```rust
use vigilnet_agent_circles::CirclesConfig;

let config = CirclesConfig {
    max_circles: 100,
    max_members_per_circle: 50,
    key_rotation_interval_days: 30,
    enable_audit_logs: true,
};
```

## Integration

- `vigilnet-agent-core`: Agent identity
- `vigilnet-crypto`: Encryption primitives
- `vigilnet-agent-transport`: Message delivery

## License

GPL-3.0
