# VigilNet Android

Android platform integration for VigilNet.

## Overview

`vigilnet-android` provides platform-specific integration for Android devices:

- **VpnService Integration**: Native Android VPN service
- **JNI Bridge**: Java/Kotlin FFI bindings
- **Network Management**: Multi-backend network switching
- **Battery Optimization**: Power-efficient operation
- **Agent Network**: Mobile-optimized agent communication

## Architecture

```
Android App (Kotlin)
    |
    v
JNI Bridge (vigilnet-android)
    |
    v
VigilNet Core (Rust)
    |
    v
TUN / Network Backends
```

## Quick Start

### Kotlin Usage

```kotlin
import net.vigilnet.VigilNetVpnService

class MyVpnService : VigilNetVpnService() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Initialize VigilNet
        val config = VigilNetConfig.builder()
            .enableTor(true)
            .enableWireGuard(true)
            .enableAgentNetwork(true)
            .build()
        
        initialize(config)
        
        // Start VPN
        val builder = Builder()
            .addAddress("10.0.0.2", 24)
            .addRoute("0.0.0.0", 0)
            .establish()
        
        startVigilNet(builder.fd)
        
        return START_STICKY
    }
}
```

## Components

### NetworkManager

Manages multiple network backends:

```rust
use vigilnet_android::NetworkManager;

let manager = NetworkManager::new()
    .with_tor(tor_client)
    .with_wireguard(wg_config)
    .with_i2p(i2p_client)
    .with_agent_network(agent);

// Auto-switch based on performance
manager.enable_smart_routing(true);
```

### VpnService

Android VPN service integration:

```rust
use vigilnet_android::vpn_service::VpnTunnel;

let tunnel = VpnTunnel::new(vpn_fd);
tunnel.start().await?;

// Process packets
while let Some(packet) = tunnel.read_packet().await {
    handle_packet(packet).await?;
}
```

### Battery Optimization

```rust
use vigilnet_android::battery::BatteryOptimizer;

let optimizer = BatteryOptimizer::new();

// Enable power saving
optimizer.enable_power_save_mode();

// Adaptive batching
optimizer.set_batch_size(32);
optimizer.set_batch_interval_ms(100);
```

### FFI Layer

JNI bindings for Kotlin interop:

```rust
#[no_mangle]
pub extern "C" fn Java_net_vigilnet_RustBridge_startNode(config_json: *const c_char) -> i32 {
    let config = parse_config(config_json);
    match start_node(config) {
        Ok(_) => 0,
        Err(e) => e.code(),
    }
}
```

## Features

### Mobile-Optimized

- **Adaptive Batching**: Batch packets based on network conditions
- **Power Management**: Respect Android Doze mode
- **Memory Efficiency**: Minimal heap allocations
- **Background Operation**: Persistent notification service

### Network Switching

Automatic fallback between networks:

1. WireGuard (fastest)
2. Tor (good privacy)
3. I2P (high privacy)
4. Mesh network (offline)

### E2EE Everywhere

Signal Protocol encryption on all transports:

```rust
use vigilnet_android::e2ee::MobileE2EE;

let e2ee = MobileE2EE::new();
e2ee.enable_for_all_transports(true);
```

## Building

### Prerequisites

```bash
# Install Android NDK
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi

# Install cargo-ndk
cargo install cargo-ndk
```

### Build Script

```bash
#!/bin/bash
# build_android.sh

cargo ndk --target aarch64-linux-android \
    --platform 21 \
    -- build --release
```

### Gradle Integration

```groovy
android {
    sourceSets {
        main {
            jniLibs.srcDirs = ['src/main/jniLibs']
        }
    }
}
```

## Configuration

```rust
use vigilnet_android::MobileConfig;

let config = MobileConfig {
    enable_battery_optimization: true,
    enable_data_saver: true,
    prefer_wifi: true,
    mesh_fallback: true,
    agent_enabled: true,
    notification_icon: "ic_vpn",
    notification_channel: "vigilnet_vpn",
};
```

## Error Handling

```rust
pub enum AndroidError {
    VpnError(String),
    NetworkError(String),
    FfiError(String),
    CoreError(vigilnet_core::Error),
}
```

## Permissions

Required Android permissions:

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.BIND_VPN_SERVICE" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
```

## Integration

- **vigilnet-core**: Core functionality
- **vigilnet-tor**: Tor on mobile
- **vigilnet-wireguard**: WireGuard tunnels
- **vigilnet-agent-mesh**: Offline mesh networking

## License

GPL-3.0
