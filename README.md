# VigilNet: A Privacy-First P2P Tunneling Network

VigilNet is a fully decentralized peer-to-peer tunneling overlay providing system-wide VPN functionality with built-in onion routing, advanced privacy features, and no central servers. Its design ensures that **all IP traffic** on participating devices is tunneled through a virtual TUN interface and relayed over an encrypted mesh. VigilNet nodes form a flat, fully meshed network (see image) where every device can serve as an entry, relay, or exit.  Traditional bootstrap servers are eliminated; instead, peers discover each other via distributed mechanisms (DHT for wide-area, mDNS for local, and multicast gossip).  The network employs multilayer (“onion”) encryption by default, ensuring that data is cryptographically encapsulated at each hop.  By default, circuits use three hops (entry, middle, exit) for strong anonymity, but users may opt for up to 10 hops for extra obfuscation.  Within this architecture, **no node has a global view** of the path or origin/destination; each only knows its immediate neighbors on a circuit, as in Tor. This design inherently makes traffic analysis extremely difficult – with thousands of possible paths, a global observer is unlikely to trace end-to-end connections.

Every node is equal and may relay traffic for others.* The network overlay is built entirely on P2P principles. **Peer discovery** uses a structured DHT (Kad-style) to find nodes by ID or metadata, supplemented by local mDNS and gossip broadcasts to bootstrap connectivity. For example, VigilNet follows a phased bootstrap (see above image): first each node discovers neighbors via DHT/mDNS, then they form an encrypted gossip mesh sharing overlay state and peer lists. Finally, an optional TUN interface may be brought up to provide full connectivity (all traffic routed) through the libp2p-based network layer. This modular phase approach (discovery → gossip → optional full tunnel) requires **no fixed seed nodes or DNS-based bootstraps**. When the system detects no public Internet, it transparently switches to peer-to-peer fallbacks: for example it can form a local ad-hoc Wi-Fi or Bluetooth mesh so that nearby devices can relay traffic for each other (much like BLE-based mesh messaging apps).  A nearby device with connectivity can serve as a gateway, ensuring even Internet-disconnected peers can participate via local mesh relays.

## Onion Routing and Encryption Layers

Each node strips one layer, knowing only the previous and next hop.*  All traffic in VigilNet is anonymous by default. Packets are encapsulated in an **onion-encrypted circuit**: the client prepends multiple layers of symmetric encryption (one layer per hop) so that each relay only decrypts one layer.  Entry nodes only see the client’s address; exit nodes only see the target address; no single hop sees both ends.  This “onion” structure (illustrated above) is the same principle used by Tor. By default circuits are length-3, but users may increase the path to up to 10 hops for extra privacy. Every hop along the path uses **session keys** (negotiated via Diffie-Hellman) so that keys are ephemeral; this prevents later key compromise from decrypting past traffic.  All in-network communication is end-to-end encrypted: payloads are AES-GCM protected, and headers carry only encrypted or hashed routing information.  Optionally, VigilNet supports *garlic routing* (bundling multiple messages together) for added plausibility, similar to I2P’s four-layer garlic encryption strategy. Critically, since endpoints are identified by public key (not IP), neither the sender’s nor receiver’s IP addresses are revealed to the network or to each other. This heavy encryption stack and randomized routing make traffic correlation extremely hard: with thousands of relay combinations, an adversary cannot feasibly observe an entire circuit.

Each node maintains no per-application state beyond routing packets; by default all IP traffic (regardless of port or protocol) is sent into the TUN interface and onion-encrypted. Advanced settings allow **per-app split tunneling**: users can exclude certain apps or route specific apps only through VigilNet. Users may also choose whether to resolve DNS locally or route DNS requests through the network. By default, *local DNS* is used to avoid inadvertent leaks, but users can configure the system to forward DNS queries through VigilNet and exit nodes if needed (similar to Tor’s DNS-through-exit option). VigilNet exit nodes maintain configurable exit policies: they may restrict which ports or hosts are reachable (e.g. blocking abuse-prone ports). For instance, an exit might allow web/SSH but refuse SMTP by default, mirroring how Tor limits abuse. Advanced users can explicitly select or exclude certain exit nodes (or whitelist internal private exits) on a per-application basis to control routing of sensitive traffic.

## Private Overlays (“Privacy Circles”)

VigilNet supports **private overlay networks** joined by shared secrets.  Users can create isolated “circles” by exchanging a key or token out-of-band; devices using the same secret form a virtual LAN overlay even if they’re geographically distant. Within such a circle, nodes behave as if on a single LAN: they discover each other via the shared overlay and can advertise local services. All circle traffic is still onion-encrypted end-to-end among members. This allows organizations or friend groups to run their own secluded VPN overlay: e.g. a home or company network that connects devices across any Internet (and even over Bluetooth/Wi-Fi links) as if on one LAN. The shared-secret approach is akin to a PSK in a VPN mesh, ensuring only authorized nodes join the private circle. No traffic from a private circle is shared with outsiders, and circle members’ node IDs are not leaked to the global network.

## Resilient Fallback Networking

If Internet connectivity fails, VigilNet seamlessly falls back to local mesh transports. It automatically detects loss of WAN and switches to peer-to-peer modes: for example, forming a Bluetooth Low Energy (BLE) mesh or Wi-Fi ad-hoc network with nearby peers. In this mode, messages hop device-to-device in a store-and-forward manner. As demonstrated by offline messaging apps like Bitchat, BLE mesh can relay data through multiple devices without any central infrastructure.  VigilNet applies the same concept: each device acts as both sender and relay (an “end device” and a “router”), extending connectivity through a local mesh. This is crucial for disaster scenarios or censorship: even if all ISPs are down, a chain of devices can carry traffic to any peer that has intermittent Internet or up to a central “gateway” device. For example, in a blackout, neighbors’ phones could form a Bluetooth mesh enabling group chat or data relay. VigilNet’s protocol automatically bridges between networks: if a peer regains Internet, it becomes an exit hop for others; if not, it still participates in the mesh. Thus, devices with no direct Internet can route through any volunteer neighbor, using multi-hop BLE/Wi-Fi until reaching a connected node. This hybrid connectivity (Internet + local mesh) ensures maximum availability.

## Trust, Reputation, and Abuse Mitigation

VigilNet adopts a **web-of-trust** style identity model rather than any token or blockchain. Each node generates ephemeral keypairs for sessions, and users may optionally “sign” others’ keys to build trust. In other words, a decentralized PKI is formed by mutual endorsement: if Alice trusts Bob’s node identity, she can vouch for Bob. Over time, a node accumulates a reputation (local to each trusting user) based on behavioral feedback. This approach is analogous to PGP’s web-of-trust. There are no coin or token incentives – trust comes purely from social proof and verifiable identity links. Nodes only reveal linkable identity information on demand (e.g. in private circles) and use fresh keys for public relaying, protecting privacy while enabling blacklisting when needed.

To deter abuse and Sybil attacks, VigilNet incorporates computational puzzles and rate controls. *Proof-of-work* challenges are required for building new circuits or advertising as a relay; this is a lightweight client puzzle (adjusted for mobile/embedded) that forces a small CPU cost. This technique, first proposed in Hashcash, effectively raises the cost of spamming or DoS efforts. Similarly, each relay or exit implements **rate-limiting** on how many new circuits or streams it will accept from any given peer per time unit, preventing flooding. Nodes monitor peers and maintain reputation scores (based on latency, error rates, and community reports). If a node consistently misbehaves (dropping packets, corrupting data, or engaging in DoS), users can submit proof-of-misconduct to community-maintained blacklists. Such blacklisting is a last resort: a node on a personal blacklist will be ignored in routing. By default, no node is universally trusted or banned — trust emerges from the overlay of many users’ endorsements. In sum, VigilNet’s hybrid model (ephemeral keys + web-of-trust reputations) minimizes reliance on a central authority, while proof-of-work, rate limits, and community governance mitigate spam and abuse.

## DNS and Routing Control

By default, VigilNet uses the **local system DNS** to resolve names, ensuring DNS queries do not leave the device unless explicitly configured. This avoids leaks and keeps default setup “do no harm.” However, advanced users can opt to route DNS queries through the encrypted overlay (using a secure DNS server reachable via the network). When enabled, queries become part of the onion stream and are resolved by exit nodes, similar to Tor’s DNS-over-exit. For fine-grained routing, VigilNet supports per-application binding: users can direct specific apps to use certain exits or bypass the network entirely. Exit nodes enforce customizable policies (allow-list of ports/addresses) so that, e.g., BitTorrent traffic can be directed out only through dedicated exits. In practice, most default exits will permit common protocols (HTTP, SSH, etc.) and refuse high-risk ports (as Tor does for SMTP). This level of routing control ensures that the overlay’s privacy guarantees are not broken by, for instance, DNS leaks or rogue traffic.

## Interfaces and Configuration

VigilNet provides both **command-line (CLI)** and **graphical (GUI)** interfaces. The Rust-based CLI offers full control for advanced users: commands to view node status, configure hops, manage keys, start/stop the tunnel interface, and adjust firewall rules. For casual users, the Electron-powered GUI (HTML5/JS frontend) offers an intuitive experience on desktop and mobile. By default the app requires *zero configuration*: once installed, it auto-generates keys, starts the TUN interface, and connects to the network with sensible defaults (3-hop onion circuits, local DNS). Users may click through a simple wizard to create or join a privacy circle (by entering a shared token). Under the hood, advanced settings allow deep configurability: customizing cryptographic parameters (e.g. cipher suites), setting hop counts, defining exit policies, and toggling fallback transports. Both interfaces integrate status dashboards (showing active peers, circuit paths, and data throughput) and logs for diagnostics. Update mechanisms are also exposed in the GUI (see *Update Strategy* below). Security-conscious defaults are enforced (all crypto strong, no tracing logs), but every option is documented for audit and fine-tuning by developers.

## Cross-Platform Support

VigilNet is designed for wide platform coverage. The initial release targets **Linux, Windows, and Android**. The core networking and crypto libraries are written in Rust (for memory safety and portability), which easily compiles to these platforms. Rust is known to support mobile (Android/iOS) and embedded targets, so porting to **macOS, iOS, and embedded devices** (e.g. routers, IoT) is planned. The GUI uses Electron, which “run\[s] natively on macOS, Windows, and Linux across all supported architectures”. Thus our cross-platform strategy is: Rust core + Electron frontend, leveraging existing cross-compilation tools. Installers/packages will be provided for each OS (e.g. .deb, .rpm, Android APK, Windows MSI, macOS DMG) and even container images. Future work includes optimizing for resource-constrained systems (lightweight Rust binaries) and exploring a Tauri-based lighter GUI for mobile. In summary, VigilNet aims for broad availability: any common OS should be able to run a node with identical functionality.

## Implementation Stack and Modularity

The VigilNet architecture is modular to facilitate future extensibility. The core P2P and crypto engine is in Rust, using libraries like \[rust-libp2p] for transport, \[ring] or \[RustCrypto] for encryption, and a custom onion-routing layer. This core exposes a plugin API so that new transports (e.g. I2P integration, or optional webRTC) or services (like a decentralized VPN accelerator) can be added. A separate Rust module handles the virtual TUN interface and packet forwarding. The CLI is also Rust-native, built with \[clap] for flags/subcommands. The GUI is an Electron app; it communicates with the Rust core via a secured IPC or gRPC channel. This separation allows the network logic to evolve independently of the UI. Plugin modules (written in Rust or supported languages) can offer analytics, alternative routing schemes, or future consensus services. Care is taken to keep the components lightweight: users may opt to run headless nodes (core + CLI only) without the GUI. All code is open source under a permissive license (e.g. MIT/Apache).

## Update Strategy

VigilNet uses a **hybrid update mechanism**. By default, clients auto-update from a cryptographically signed, official repository (over HTTPS). Electron’s autoUpdater (or similar) ensures timely patches for all platforms. To maintain privacy and resilience, we also provide *optional P2P distribution* of updates: updates (release binaries and diffs) are chunked and shared via the VigilNet network itself (akin to IPFS). Clients verify signatures on any update before applying, so a malicious peer cannot inject bad code. Users may opt into P2P-updates for censorship resistance: even if our official servers are blocked, the community overlay can propagate new versions. All updates are signed with our project keys; clients refuse unsigned or tampered files. Rollbacks are prevented by requiring signatures from the latest key (old keys are rotated regularly). This hybrid approach combines the reliability of central releases with the robustness of peer-to-peer propagation.

## Governance and Community

VigilNet is envisioned as a **community-driven project**. There is no blockchain or cryptocurrency; governance is reputation-based and meritocratic. Development is open to volunteers and organizations. Users can set up and manage *private subnets* (circles) with their own admission policies – these operate under the same protocol but with localized control. The core protocol is maintained by a small group of maintainers, but protocol changes are proposed via GitHub/RFCs with community discussion. Reputation accrues through code contributions, reputable node operation, and peer endorsements (web-of-trust). There are no token incentives; instead, recognition comes from trusted relationships and leaderboards (for example, highlighting reliable exit node operators or contributors). Misbehaving code submissions are policed by code review and audit, much like other open-source projects. Key project decisions (like release timing or major feature scope) may involve community voting by trusted members, but day-to-day operations remain decentralized. In short, VigilNet’s governance mirrors its trust model: decentralized, reputation-based, and resilient to capture.

## Threat Model and Mitigations

**Adversaries:** VigilNet assumes adversaries may include global passive observers, targeted local snoops, or malicious peers. Attackers can attempt traffic analysis, Sybil attacks (many fake nodes), DoS flooding, or injection of bad data. Devices may be compromised, so we cannot trust a node to behave honestly.

**Mitigations:** Onion routing itself thwarts simple traffic analysis: since each node only sees one encryption layer, an eavesdropper cannot link source and destination without controlling all hops. VigilNet also mitigates risk of node compromise: all forward traffic is encrypted and authenticated end-to-end, so a rogue relay cannot alter payloads undetectably. Sybil and spam are handled by proof-of-work and rate-limiting; newcomers must expend CPU cost to join or advertise, discouraging mass-node attacks. The web-of-trust layer helps resist Sybils long-term, since reputable identities must earn endorsements. DoS attacks (packet floods or handshake exploits) are limited by requiring puzzles and by limiting connection rates on each node. Malicious exit traffic is controlled via exit policies (e.g. blocking spam ports). Furthermore, fallback mesh ensures connectivity even under censorship/partition: if Internet routes are blocked, local wireless links keep the network alive. Any remaining threats (like timing analysis) are acknowledged as research challenges; VigilNet focuses on practical, deployable defenses (strong encryption, padding randomization, multiple paths) rather than perfect anonymity. As in Tor’s design philosophy, usability and growth are balanced against ideal security; VigilNet leaves room for future traffic-shaping and padding mitigations if needed.

## Use Cases

* **Censorship Circumvention:** Users in repressive regimes can route through international VigilNet peers to access the open Internet. The onion hop-chain hides both origin and content from local censors. Since VigilNet has no centralized choke points, blocking requires shutting down *all* peers (impractical at scale). Private overlays allow organization staff to coordinate even if public networks are censored.
* **Disaster & Offline Coordination:** In emergencies (earthquakes, wars, blackouts), VigilNet enables ad-hoc communication. First responders’ devices form a local mesh (BLE/Wi-Fi) to exchange maps, coordinates, or voice/data. As noted in Bitchat’s analysis, BLE mesh can maintain community networks when towers fail. VigilNet extends this by providing end-to-end encryption and multi-hop long range via Bluetooth. Even without power, battery-powered nodes relay critical messages with privacy.
* **Secure IoT and Enterprise VPN:** Companies can use VigilNet as a zero-config VPN across branch offices. Devices anywhere in the world join a private circle and appear on a single virtual subnet. Unlike classic VPNs, there are no central gateways—any machine can act as an exit. IoT devices gain secure, encrypted connectivity even on public networks. The overlay’s built-in anonymity protects device identities.
* **Mobile Privacy:** On untrusted Wi-Fi (cafés, hotels), VigilNet automatically tunnels all traffic through peers, preventing local hotspot operators from snooping. Users can use public Internet safely by piggybacking on other random exit nodes, similar to Tor for mobile.
* **Mesh Social Apps:** Developers can build decentralized apps (chat, file sharing) on top of VigilNet. For example, a P2P social media or chat app could use VigilNet’s P2P network instead of centralized servers, automatically benefiting from anonymity and encryption. The TUN interface also means any legacy app (email, browser) can use VigilNet without modification.

## Deployment and Distribution

VigilNet will be published as open-source on GitHub. Releases will include pre-built binaries for Linux (x86\_64, ARM), Windows, Android (APK), and soon macOS. We will also package distro-specific installers (DEB, RPM) and an Android Store listing. For ease of discovery, an official website will list stable download links and the public project signing key. Optionally, a Tor hidden service and IPFS gateway may mirror the downloads for censorship resistance. Container images (Docker, etc.) will allow deployment on servers or routers. Documentation will cover installing and configuring the system, including snapshots for cloud providers (for quickly spinning up exit relays). To bootstrap initial peers, we may release a small set of “welcome peers” IP lists (which are themselves just normal community nodes) in the installer – but these are not special servers, just entrypoints the same as any other node. In operation, each node periodically publishes its address to the distributed network database (DHT), so any peer can be found without central coordination. Users are encouraged to run nodes and share bandwidth to grow VigilNet organically.

## Scalability, Performance, and Roadmap

VigilNet is designed to **scale to tens of thousands of nodes** initially, then ultimately to the scale of Tor (hundreds of thousands). Its flat mesh has O(n) connectivity overhead per node, and the use of a DHT means discovery scales as \$O(\log n)\$ lookups. Performance goals include: adding no more than \~50–100 ms latency per hop (target 150 ms circuit RTT over 3 hops in normal conditions), and maintaining at least a few Mbps throughput per peer for typical links. Packet sizes are bounded (e.g. 2 KB cells) to limit buffer usage. We will run benchmarks and continuously optimize (e.g. using Rust’s async for concurrency, or native drivers for cryptography). The planned roadmap is:

1. **v1.0 (Initial Release):** Basic core networking and onion routing, Linux/Windows/Android clients, automatic peer discovery (DHT/mDNS/gossip), TUN integration, CLI & GUI, basic DNS and routing controls. Proof-of-work and rate-limiting enabled.
2. **v1.1:** Add multi-hop customization (user-adjustable hop count), GUI improvements, cross-platform tests, packaged installs (Deb, APK, etc.), and documentation.
3. **v2.0:** Private circle support with key exchange; advanced exit-selection GUI; P2P update mechanism; integration of Bluetooth/Wi-Fi fallback transports for offline mode.
4. **Future (beyond 2.0):** Mobile iOS support, WebAssembly/embedded (IoT) port, performance optimizations (e.g. kernel TUN drivers), optional mixing/padding, and plugin marketplace for extension modules.
   Throughout, scalability testing will guide optimizations. We will aim for a responsive, resilient network: for instance, ensure that 1000 concurrent users incur <500 ms connection setup and that the system handles churn gracefully.

## References

VigilNet’s design draws on proven research and systems. Its onion-routing is modeled on Tor and I2P. Decentralized discovery follows libp2p/Kademlia principles and ideas from projects like Kairos/EdgeVPN. Spam and Sybil defenses use proof-of-work as in Hashcash. The web-of-trust model is inspired by PGP/GnuPG’s approach. Offline mesh fallback takes cues from BLE-mesh messaging networks. Finally, cross-platform choices (Rust, Electron) are industry-standard for multi-OS apps. These sources validate VigilNet’s core strategies for privacy, decentralization, and resilience.
