# VigilNet TUN

TUN interface for system-wide VPN functionality.

## Overview

`vigilnet-tun` provides virtual network device support for VigilNet:

- **TUN Device Management**: Create and configure virtual interfaces
- **Packet Processing**: IP packet parsing and manipulation
- **Firewall**: Packet filtering and rules
- **DHCP Guard**: Prevent DHCP leaks
- **Network Namespace**: Linux namespace support

## Quick Start

```rust
use vigilnet_tun::{TunConfig, TunDevice};

// Configure TUN device
let config = TunConfig {
    name: "vigilnet0".to_string(),
    mtu: 1500,
    ipv4: Some("10.0.0.1/24".to_string()),
    ipv6: None,
};

// Create device
let device = TunDevice::new(config)?;
device.up()?;

// Read packets
let mut buf = [0u8; 1500];
let n = device.read(&mut buf).await?;

// Process packet
let packet = IpPacket::parse(&buf[..n])?;
println!("Packet: {:?}", packet);

// Write packets
device.write(&response_packet).await?;
```

## TUN Configuration

```rust
use vigilnet_tun::TunConfig;

let config = TunConfig {
    name: "vigilnet0".to_string(),
    mtu: 1500,
    ipv4: Some("10.0.0.1/24".to_string()),
    ipv6: Some("fd00::1/64".to_string()),
};
```

## Packet Processing

Parse and manipulate IP packets:

```rust
use vigilnet_tun::IpPacket;

// Parse incoming packet
let packet = IpPacket::parse(&buf)?;

match packet {
    IpPacket::Ipv4(ipv4) => {
        println!("Source: {}", ipv4.source());
        println!("Destination: {}", ipv4.destination());
        println!("Protocol: {:?}", ipv4.protocol());
    }
    IpPacket::Ipv6(ipv6) => {
        // Handle IPv6
    }
}
```

## Firewall

Packet filtering:

```rust
use vigilnet_tun::{Firewall, FirewallConfig, FirewallRule};

let config = FirewallConfig::default()
    .allow_incoming(443)  // HTTPS
    .allow_incoming(80)   // HTTP
    .block_outgoing(25);  // Block SMTP

let firewall = Firewall::new(config)?;

if firewall.allow(&packet)? {
    // Forward packet
} else {
    // Drop packet
}
```

## DHCP Guard

Prevent DNS leaks via DHCP:

```rust
use vigilnet_tun::DhcpGuard;

let guard = DhcpGuard::new();
guard.enable_protection()?;

// Intercept DHCP responses
if guard.is_dhcp_packet(&packet) {
    guard.block_or_rewrite(&packet)?;
}
```

## Network Namespace (Linux)

```rust
use vigilnet_tun::namespace::NetworkNamespace;

#[cfg(unix)]
{
    let ns = NetworkNamespace::new("vigilnet")?;
    ns.enter()?;
    
    // Now in isolated namespace
    
    ns.exit()?;
}
```

## Platform Support

- **Linux**: Full support with namespaces
- **macOS**: TUN device support
- **Windows**: Wintun integration
- **Android**: VpnService integration (via `vigilnet-android`)

## Integration

Used by:
- `vigilnet-core`: System-level VPN
- `vigilnet-android`: Android VPN service

## License

GPL-3.0
