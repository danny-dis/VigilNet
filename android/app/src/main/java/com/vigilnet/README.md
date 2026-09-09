# VigilNet Android App

Complete Jetpack Compose UI for the VigilNet privacy-focused VPN and mesh networking application.

## Features

- **VPN Connection**: Multi-network backend support (Tor, I2P, WireGuard, Nym, etc.)
- **Agent Management**: Start/stop mesh, circle, and research agents
- **Circles**: Create and join trust circles with cryptographic invites
- **Mesh Network**: Visualize and manage P2P mesh connections

## Architecture

### Structure
```
android/app/src/main/java/com/vigilnet/
├── MainActivity.kt              # Main entry point with navigation
├── ffi/
│   └── RustBridge.kt           # JNI bindings to Rust library
├── service/
│   └── VigilNetVpnService.kt   # Android VpnService implementation
├── ui/
│   ├── screens/
│   │   ├── HomeScreen.kt       # Connection toggle & stats
│   │   ├── AgentsScreen.kt     # Agent management
│   │   ├── CirclesScreen.kt    # Circle management
│   │   └── MeshScreen.kt       # Mesh network status
│   ├── viewmodels/
│   │   ├── ConnectionViewModel.kt
│   │   ├── AgentViewModel.kt
│   │   └── CircleViewModel.kt
│   └── theme/
│       ├── Color.kt            # Dark theme colors
│       ├── Theme.kt            # Material3 theme setup
│       └── Type.kt             # Typography
```

## Setup

### Prerequisites

1. Android Studio Arctic Fox or later
2. Android SDK 24+ (Android 7.0)
3. Rust toolchain with Android targets
4. NDK installed

### Build Instructions

1. Build the Rust library:
```bash
cd crates/vigilnet-android
cargo build --release --target aarch64-linux-android
```

2. Copy the library to jniLibs:
```bash
cp target/aarch64-linux-android/release/libvigilnet.so \
   android/app/src/main/jniLibs/arm64-v8a/
```

3. Open the `android` folder in Android Studio

4. Build and run the application

### Gradle Dependencies

Add to `android/app/build.gradle`:

```kotlin
dependencies {
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("androidx.activity:activity-compose:1.8.2")
    implementation(platform("androidx.compose:compose-bom:2024.02.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.navigation:navigation-compose:2.7.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.7.0")
}
```

## FFI Integration

The app communicates with the Rust backend through JNI. The `RustBridge` object provides access to:

- VPN tunnel management
- Network backend switching
- Agent lifecycle
- Circle creation and invites
- Battery optimization
- Split tunneling

## Screens

### Home
- Connection toggle with animated status
- Real-time traffic statistics
- Network backend selection (Tor, I2P, WireGuard, Nym)
- Multi-hop routing chain configuration

### Agents
- Initialize and manage mobile agents
- Start/stop mesh fallback
- Monitor agent status and peer counts
- Send messages to agents

### Circles
- Create trust circles (Public, Private, Audit)
- Generate cryptographic invites with threshold sharing
- Join circles with invite codes
- Send messages to circle members

### Mesh
- Mesh network status visualization
- Transport protocol indicators (BLE, WiFi, LoRa)
- Connection graph showing peer topology
- Mesh statistics and relay metrics

## Security

- All FFI calls go through `RustBridge` with proper error handling
- VPN service runs as foreground service with notification
- Battery status sent to Rust for power-aware routing
- Network changes propagated to Rust backend

## License

Same as VigilNet project
