//! Multi-Network Manager
//!
//! Manages multiple network backends (Clearnet, Tor, I2P, Freenet, WireGuard, Nym)
//! allowing the user to select which networks to route traffic through.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tracing::{info, warn, error, trace};

use crate::vpn_service::TunPacket;
use crate::agents::MobileAgentManager;
use crate::tun_stack::{TunStack, BackendProxy, BackendStream};

/// Available network backends
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkBackend {
    /// Direct clearnet (TCP/QUIC via libp2p)
    Clearnet,
    /// Tor network via Arti
    Tor,
    /// I2P network via SAM/Emissary
    I2p,
    /// Freenet / Hyphanet
    Freenet,
    /// Yggdrasil IPv6 overlay
    Yggdrasil,
    /// Lokinet onion router
    Lokinet,
    /// GNUnet framework
    GnuNet,
    /// CJDNS encrypted mesh
    Cjdns,
    /// WireGuard tunnel
    WireGuard,
    /// Nym mixnet
    Nym,
    /// IPFS content routing
    Ipfs,
    /// ZeroNet decentralized web
    ZeroNet,
}

impl NetworkBackend {
    /// Get human-readable name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Clearnet => "Clearnet (Direct)",
            Self::Tor => "Tor Network",
            Self::I2p => "I2P Network",
            Self::Freenet => "Freenet / Hyphanet",
            Self::Yggdrasil => "Yggdrasil Mesh",
            Self::Lokinet => "Lokinet",
            Self::GnuNet => "GNUnet",
            Self::Cjdns => "CJDNS Mesh",
            Self::WireGuard => "WireGuard Tunnel",
            Self::Nym => "Nym Mixnet",
            Self::Ipfs => "IPFS",
            Self::ZeroNet => "ZeroNet",
        }
    }

    /// Get anonymity level (0-10)
    pub fn anonymity_level(&self) -> u8 {
        match self {
            Self::Clearnet => 0,
            Self::WireGuard => 3,
            Self::Yggdrasil => 4,
            Self::Cjdns => 4,
            Self::Ipfs => 3,
            Self::ZeroNet => 4,
            Self::GnuNet => 6,
            Self::Lokinet => 7,
            Self::Freenet => 7,
            Self::Tor => 8,
            Self::I2p => 8,
            Self::Nym => 9,
        }
    }

    /// Whether this backend is currently implementable
    pub fn is_available(&self) -> bool {
        match self {
            Self::Clearnet => true,
            Self::Tor => true,      // via arti
            Self::I2p => true,      // via i2p-rs / emissary
            Self::Freenet => true,  // via freenet-core
            Self::WireGuard => true, // via boringtun
            Self::Nym => true,      // via nym-sdk
            Self::Yggdrasil => false, // TODO
            Self::Lokinet => false,   // TODO
            Self::GnuNet => false,    // TODO
            Self::Cjdns => false,     // TODO
            Self::Ipfs => false,      // TODO
            Self::ZeroNet => false,   // TODO
        }
    }
}

/// Status of a network backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatus {
    /// Backend identifier
    pub backend: NetworkBackend,
    /// Whether enabled by user
    pub enabled: bool,
    /// Whether currently connected
    pub connected: bool,
    /// Number of peers/relays
    pub peer_count: usize,
    /// Estimated latency in ms
    pub latency_ms: Option<u32>,
    /// Bytes sent through this backend
    pub bytes_sent: u64,
    /// Bytes received through this backend
    pub bytes_received: u64,
    /// Human-readable status message
    pub status_message: String,
}

impl NetworkStatus {
    fn new(backend: NetworkBackend) -> Self {
        Self {
            backend,
            enabled: false,
            connected: false,
            peer_count: 0,
            latency_ms: None,
            bytes_sent: 0,
            bytes_received: 0,
            status_message: "Not initialized".to_string(),
        }
    }
}

/// Network chain for multi-hop routing
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkChain {
    /// Ordered list of backends to route through
    pub chain: Vec<NetworkBackend>,
}

/// Network routing policy for per-app routing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingPolicy {
    /// Default backend for all traffic
    pub default_backend: NetworkBackend,
    /// Default chain for multi-hop routing (ignored if empty)
    pub default_chain: NetworkChain,
    /// Per-app overrides (package name -> backend)
    pub app_overrides: HashMap<String, NetworkBackend>,
    /// Per-app chain overrides (package name -> chain)
    pub app_chains: HashMap<String, NetworkChain>,
    /// Domains to exclude from tunnel (split tunneling)
    pub excluded_domains: Vec<String>,
    /// Apps to exclude from tunnel
    pub excluded_apps: Vec<String>,
}

/// Global configuration for VigilNet engine persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VigilNetConfig {
    /// Routing policy (Split Tunneling, Multi-Hop)
    pub routing_policy: RoutingPolicy,
    /// Configured Tor bridges
    pub tor_bridges: Vec<String>,
    /// Selected active backends
    pub enabled_backends: Vec<NetworkBackend>,
}

impl Default for VigilNetConfig {
    fn default() -> Self {
        Self {
            routing_policy: RoutingPolicy::default(),
            tor_bridges: Vec::new(),
            enabled_backends: vec![NetworkBackend::Clearnet],
        }
    }
}

impl Default for RoutingPolicy {
    fn default() -> Self {
        Self {
            default_backend: NetworkBackend::Clearnet,
            default_chain: NetworkChain::default(),
            app_overrides: HashMap::new(),
            app_chains: HashMap::new(),
            excluded_domains: Vec::new(),
            excluded_apps: Vec::new(),
        }
    }
}

/// Multi-network manager
/// 
/// Coordinates multiple network backends, handles routing decisions,
/// and provides a unified interface for the Android UI layer.
pub struct NetworkManager {
    /// Status of each backend
    statuses: Arc<RwLock<HashMap<NetworkBackend, NetworkStatus>>>,
    /// Routing policy
    policy: Arc<arc_swap::ArcSwap<RoutingPolicy>>,
    /// VigilNet core node
    node: Option<Arc<vigilnet_core::Node>>,
    /// Channel to send packets to TUN interface
    packet_to_tun: Option<mpsc::Sender<TunPacket>>,
    /// Tor Client instance
    tor_client: Arc<RwLock<vigilnet_tor::TorClient>>,
    /// Channel to send packets to the userspace TCP stack (TunStack)
    tun_stack_tx: Option<mpsc::Sender<TunPacket>>,
    /// Mesh Fallback Agent
    mesh_fallback: Arc<RwLock<vigilnet_agent_mesh::MeshFallback>>,
    /// WireGuard Tunnel
    wg_tunnel: Arc<RwLock<vigilnet_wireguard::tunnel::WgTunnel>>,
    /// I2P Client
    i2p_client: Arc<RwLock<vigilnet_i2p::sam::SamClient>>,
    /// Nym Mixnet Client
    nym_client: Arc<RwLock<vigilnet_nym::client::NymClient>>,
    /// Freenet Node
    freenet_node: Arc<RwLock<vigilnet_freenet::node::FreenetNode>>,
    /// Base path for storage
    storage_path: Option<std::path::PathBuf>,
    /// Mobile Agent Manager
    agent_manager: Arc<RwLock<Option<MobileAgentManager>>>,
}

impl NetworkManager {
    /// Create a new NetworkManager
    pub fn new() -> Self {
        let mut statuses = HashMap::new();
        
        // Initialize all backends as disabled
        for backend in [
            NetworkBackend::Clearnet,
            NetworkBackend::Tor,
            NetworkBackend::I2p,
            NetworkBackend::Freenet,
            NetworkBackend::Yggdrasil,
            NetworkBackend::Lokinet,
            NetworkBackend::GnuNet,
            NetworkBackend::Cjdns,
            NetworkBackend::WireGuard,
            NetworkBackend::Nym,
            NetworkBackend::Ipfs,
            NetworkBackend::ZeroNet,
        ] {
            statuses.insert(backend, NetworkStatus::new(backend));
        }

        // Initialize Mesh Agent
        let mesh_config = vigilnet_agent_mesh::MeshFallbackConfig::default();
        let mesh_fallback = match vigilnet_agent_mesh::MeshFallback::new(mesh_config) {
            Ok(m) => m,
            Err(e) => {
                error!("Failed to initialize Mesh Agent: {}", e);
                panic!("Mesh Agent Init Failed: {}", e);
            }
        };

        Self {
            statuses: Arc::new(RwLock::new(statuses)),
            policy: Arc::new(arc_swap::ArcSwap::from_pointee(RoutingPolicy::default())),
            node: None,
            packet_to_tun: None,
            tor_client: Arc::new(RwLock::new(vigilnet_tor::TorClient::new())),
            tun_stack_tx: None,
            mesh_fallback: Arc::new(RwLock::new(mesh_fallback)),
            wg_tunnel: Arc::new(RwLock::new(vigilnet_wireguard::tunnel::WgTunnel::new())),
            i2p_client: Arc::new(RwLock::new(vigilnet_i2p::sam::SamClient::default_bridge())),
            nym_client: Arc::new(RwLock::new(vigilnet_nym::client::NymClient::new())),
            freenet_node: Arc::new(RwLock::new(vigilnet_freenet::node::FreenetNode::new("/data/user/0/net.vigilnet.app/files/freenet"))),
            storage_path: None,
            agent_manager: Arc::new(RwLock::new(None)),
        }
    }

    /// Set the storage path and load existing config if any
    pub async fn set_storage_path(&mut self, path: String) {
        let p = std::path::PathBuf::from(path);
        if let Err(e) = tokio::fs::create_dir_all(&p).await {
            error!("Failed to create storage directory: {}", e);
        }
        self.storage_path = Some(p);
        info!("Storage path set to: {:?}", self.storage_path);

        if let Err(e) = self.load_config().await {
            warn!("Could not load configuration from disk: {}", e);
        }
    }

    /// Save current configuration to disk
    pub async fn save_config(&self) -> crate::Result<()> {
        let storage_path = match &self.storage_path {
            Some(p) => p,
            None => return Ok(()),
        };

        let config_file = storage_path.join("vigilnet_config.json");
        
        let policy = self.policy.load();
        let statuses = self.statuses.read().await;
        
        let mut enabled_backends = Vec::new();
        for (backend, status) in statuses.iter() {
            if status.enabled {
                enabled_backends.push(*backend);
            }
        }

        let config = VigilNetConfig {
            routing_policy: policy.clone(),
            tor_bridges: Vec::new(), // Placeholder, extract if needed
            enabled_backends,
        };

        let json = serde_json::to_string_pretty(&config)?;
        tokio::fs::write(config_file, json).await?;
        info!("Configuration saved to disk");
        Ok(())
    }

    /// Load configuration from disk
    pub async fn load_config(&self) -> crate::Result<()> {
        let storage_path = match &self.storage_path {
            Some(p) => p,
            None => return Ok(()),
        };

        let config_file = storage_path.join("vigilnet_config.json");
        if !config_file.exists() {
            return Ok(());
        }

        let json = tokio::fs::read_to_string(config_file).await?;
        let config: VigilNetConfig = serde_json::from_str(&json)?;
        
        // Restore policy
        self.policy.store(Arc::new(config.routing_policy));
        
        // Restore enabled status
        let mut statuses = self.statuses.write().await;
        for backend in config.enabled_backends {
            if let Some(status) = statuses.get_mut(&backend) {
                status.enabled = true;
            }
        }
        
        info!("Configuration restored from disk");
        Ok(())
    }

    /// Set the channel to send packets back to the TUN interface
    pub fn set_tun_sender(&mut self, sender: mpsc::Sender<TunPacket>) {
        info!("TUN sender configured for NetworkManager");
        self.packet_to_tun = Some(sender);
    }

    /// Set the VigilNet core node
    pub fn set_node(&mut self, node: Arc<vigilnet_core::Node>) {
        info!("Core node registered with NetworkManager");
        self.node = Some(node);
    }

    /// Handle an incoming packet from the TUN interface
    pub async fn handle_packet(&self, packet: TunPacket) {
        let (backend, chain) = self.resolve_routing(None, None).await;
        
        if chain.chain.len() > 1 {
            self.route_multi_hop(packet, chain).await;
        } else {
            self.route_single_hop(packet, backend).await;
        }
    }

    async fn route_single_hop(&self, packet: TunPacket, backend: NetworkBackend) {
        match backend {
            NetworkBackend::Tor => {
                if let Some(tx) = &self.tun_stack_tx {
                    let _ = tx.send(packet).await;
                }
            }
            NetworkBackend::WireGuard => {
                let mut wg = self.wg_tunnel.write().await;
                let _ = wg.handle_output_packet(&packet.data).await;
            }
            _ => {
                warn!("Single-hop routing for {:?} not fully implemented", backend);
            }
        }
    }

    async fn route_multi_hop(&self, packet: TunPacket, chain: NetworkChain) {
        trace!("Routing packet through chain: {:?}", chain.chain);
        // Multi-hop routing algorithm (Layered Encapsulation):
        // app_packet -> [Tor (Onion)] -> [WireGuard (VPN)] -> NIC
        // The first backend in the chain is usually the 'outermost' (the one the packet hits first from the TUN).
        // Wait, logically it's the reverse: 
        // App -> TunStack (Tor) -> WgTunnel (WireGuard) -> Internet
        // So the chain [Tor, WireGuard] means Tor over WireGuard.
        
        // Simple implementation for Tor over VPN:
        if chain.chain.len() == 2 && chain.chain[0] == NetworkBackend::Tor && chain.chain[1] == NetworkBackend::WireGuard {
            trace!("Multi-hop: Routing Tor over WireGuard");
            // 1. Packet goes into TunStack (Tor entry)
            // 2. TunStack establishes Tor circuits
            // 3. TunStack's socket needs to be bound to the WireGuard tunnel's virtual interface
            // TODO: Implementation of bind-to-backend in TunStack
            if let Some(tx) = &self.tun_stack_tx {
                let _ = tx.send(packet).await;
            }
        } else {
             warn!("Complex multi-hop chains not yet implemented, falling back to first hop");
             self.route_single_hop(packet, chain.chain[0]).await;
        }
    }

    /// Enable a network backend
    pub async fn enable_backend(&mut self, backend: NetworkBackend) -> crate::Result<()> {
        if !backend.is_available() {
            return Err(crate::AndroidError::NetworkError(
                format!("{} is not yet implemented", backend.display_name())
            ));
        }

        info!("Enabling network backend: {}", backend.display_name());

        let mut statuses = self.statuses.write().await;
        if let Some(status) = statuses.get_mut(&backend) {
            status.enabled = true;
            status.status_message = "Connecting...".to_string();
        }
        drop(statuses); // Release lock before long async ops

        // Backend-specific initialization
        match backend {
            NetworkBackend::Clearnet => {
                self.init_clearnet().await?;
            }
            NetworkBackend::Tor => {
                self.init_tor().await?;
            }
            NetworkBackend::I2p => {
                self.init_i2p().await?;
            }
            NetworkBackend::Freenet => {
                self.init_freenet().await?;
            }
            NetworkBackend::WireGuard => {
                self.init_wireguard().await?;
            }
            NetworkBackend::Nym => {
                self.init_nym().await?;
            }
            _ => {
                warn!("Backend {} not yet implemented", backend.display_name());
                return Err(crate::AndroidError::NetworkError(
                    format!("{} support coming soon", backend.display_name())
                ));
            }
        }

        // Mark as connected
        let mut statuses = self.statuses.write().await;
        if let Some(status) = statuses.get_mut(&backend) {
            status.connected = true;
            status.status_message = "Connected".to_string();
        }

        Ok(())
    }

    /// Disable a network backend
    pub async fn disable_backend(&mut self, backend: NetworkBackend) -> crate::Result<()> {
        info!("Disabling network backend: {}", backend.display_name());

        let mut statuses = self.statuses.write().await;
        if let Some(status) = statuses.get_mut(&backend) {
            status.enabled = false;
            status.connected = false;
            status.status_message = "Disconnected".to_string();
        }
        
        // If disabling Tor, we should also stop tun_stack (optional, for now we keep it running or restart on enable)
        // Ideally we drop tun_stack_tx to signal the task to stop?
        if backend == NetworkBackend::Tor {
            // self.tun_stack_tx = None; // This drops the sender, causing the stack loop to exit
        }

        Ok(())
    }

    /// Smoothly switch to a new default backend (Make-Before-Break)
    pub async fn switch_backend(&mut self, new_backend: NetworkBackend) -> crate::Result<()> {
        let old_backend = self.get_policy().await.default_backend;

        if old_backend == new_backend {
            info!("Already using backend: {}", new_backend.display_name());
            return Ok(());
        }

        info!("Switching backend: {} -> {}", old_backend.display_name(), new_backend.display_name());

        // 1. Enable new backend
        self.enable_backend(new_backend).await?;

        // 2. Wait for connection (stub: check status immediately)
        let connected = if let Some(status) = self.get_status(new_backend).await {
            status.connected
        } else {
            false
        };

        if !connected {
            // Rollback
            let _ = self.disable_backend(new_backend).await;
            return Err(crate::AndroidError::NetworkError(
                format!("Failed to connect to {}", new_backend.display_name())
            ));
        }

        // 3. Update routing policy
        let mut policy = self.policy.write().await;
        policy.default_backend = new_backend;
        drop(policy); // release lock

        // 4. Disable old backend
        if old_backend != NetworkBackend::Clearnet {
             self.disable_backend(old_backend).await?;
        }

        info!("Successfully switched to {}", new_backend.display_name());
        Ok(())
    }

    /// Get the status of all backends
    pub async fn get_all_statuses(&self) -> Vec<NetworkStatus> {
        let statuses = self.statuses.read().await;
        statuses.values().cloned().collect()
    }

    /// Get status of a specific backend
    pub async fn get_status(&self, backend: NetworkBackend) -> Option<NetworkStatus> {
        let statuses = self.statuses.read().await;
        statuses.get(&backend).cloned()
    }

    /// Set the routing policy
    pub async fn set_policy(&self, policy: RoutingPolicy) {
        self.policy.store(Arc::new(policy));
        let _ = self.save_config().await;
    }

    /// Get the current routing policy
    pub async fn get_policy(&self) -> RoutingPolicy {
        (**self.policy.load()).clone()
    }

    /// Handle network connectivity changes (e.g. Wi-Fi to Mobile)
    pub async fn on_network_changed(&self, is_wifi: bool, is_mobile: bool) {
        info!("Network changed: WIFI={}, MOBILE={}", is_wifi, is_mobile);
        
        // Connectivity adaptation logic:
        // 1. If currently on Tor, check if circuits need re-bootstrap or if bridges need to change?
        // 2. If on WireGuard, the tunnel should handle endpoint roaming automatically, 
        //    but we might want to log or trigger a handshake.
        
        // For now, we mainly log it. In future phases, we will add backend-specific re-binds.
        if !is_wifi && !is_mobile {
            warn!("Connectivity lost! Keeping VPN tunnel up (Fail-Closed).");
        } else {
            info!("Connectivity restored/changed. Adapting backends...");
        }
    }

    /// Determine which backend(s) to use for a given app/domain
    pub async fn resolve_routing(&self, package_name: Option<&str>, domain: Option<&str>) -> (NetworkBackend, NetworkChain) {
        let policy = self.policy.load();

        // Check if domain is excluded
        if let Some(domain) = domain {
            if policy.excluded_domains.iter().any(|d| domain.ends_with(d)) {
                return (NetworkBackend::Clearnet, NetworkChain::default());
            }
        }

        // Check per-app override
        if let Some(pkg) = package_name {
            if policy.excluded_apps.contains(&pkg.to_string()) {
                return (NetworkBackend::Clearnet, NetworkChain::default());
            }
            
            if let Some(chain) = policy.app_chains.get(pkg) {
                if !chain.chain.is_empty() {
                    return (chain.chain[0], chain.clone());
                }
            }

            if let Some(backend) = policy.app_overrides.get(pkg) {
                return (*backend, NetworkChain::default());
            }
        }

        if !policy.default_chain.chain.is_empty() {
             (policy.default_chain.chain[0], policy.default_chain.clone())
        } else {
             (policy.default_backend, NetworkChain::default())
        }
    }

    /// Add an app to the excluded list (split tunneling)
    pub async fn add_excluded_app(&self, package_name: String) {
        info!("Excluding app from tunnel: {}", package_name);
        {
            let current = self.policy.load();
            if !current.excluded_apps.contains(&package_name) {
                let mut new_policy = (**current).clone();
                new_policy.excluded_apps.push(package_name);
                self.policy.store(Arc::new(new_policy));
                info!("App added to split-tunnel exclusions");
            }
        }
        let _ = self.save_config().await;
    }

    /// Remove an app from the excluded list
    pub async fn remove_excluded_app(&self, package_name: &str) {
        {
            let current = self.policy.load();
            if current.excluded_apps.iter().any(|a| a == package_name) {
                let mut new_policy = (**current).clone();
                new_policy.excluded_apps.retain(|a| a != package_name);
                self.policy.store(Arc::new(new_policy));
                info!("App removed from split-tunnel exclusions");
            }
        }
        let _ = self.save_config().await;
    }

    /// Add a domain to the excluded list
    pub async fn add_excluded_domain(&self, domain: String) {
        {
            let current = self.policy.load();
            if !current.excluded_domains.contains(&domain) {
                let mut new_policy = (**current).clone();
                new_policy.excluded_domains.push(domain);
                self.policy.store(Arc::new(new_policy));
                info!("Domain added to split-tunnel exclusions");
            }
        }
        let _ = self.save_config().await;
    }

    /// Remove a domain from the excluded list
    pub async fn remove_excluded_domain(&self, domain: &str) {
        {
            let current = self.policy.load();
            if current.excluded_domains.iter().any(|d| d == domain) {
                let mut new_policy = (**current).clone();
                new_policy.excluded_domains.retain(|d| d != domain);
                self.policy.store(Arc::new(new_policy));
                info!("Domain removed from split-tunnel exclusions");
            }
        }
        let _ = self.save_config().await;
    }

    /// Set Tor bridges (e.g. from UI)
    pub async fn set_tor_bridges(&self, bridges: Vec<String>) {
        {
            let mut client = self.tor_client.write().await;
            client.set_bridges(bridges);
            info!("Updated Tor bridge configuration");
        }
        let _ = self.save_config().await;
    }

    /// Start Mesh Agent
    pub async fn start_mesh(&self) -> crate::Result<()> {
        info!("Starting Mesh Agent...");
        let mesh = self.mesh_fallback.read().await;
        // mesh.run() is async and typically long-running. 
        // We should likely spawn it or just ensure it starts its background tasks.
        // Looking at lib.rs usage: `mesh.run().await?`. If it blocks, we need to spawn.
        // Assuming run() blocks:
        
        let mesh_clone = self.mesh_fallback.clone();
        tokio::spawn(async move {
            let mesh = mesh_clone.read().await;
            if let Err(e) = mesh.run().await {
                 error!("Mesh Agent runtime error: {}", e);
            }
        });
        
        Ok(())
    }

    /// Stop Mesh Agent
    pub async fn stop_mesh(&self) -> crate::Result<()> {
        info!("Stopping Mesh Agent...");
        // TODO: Implement stop mechanism in MeshFallback
        Ok(())
    }

    // --- Backend initialization stubs ---

    async fn init_clearnet(&self) -> crate::Result<()> {
        info!("Initializing Clearnet (direct libp2p) backend");
        // The core node already handles clearnet via libp2p
        Ok(())
    }

    async fn init_tor(&mut self) -> crate::Result<()> {
        info!("Initializing Tor (Arti) backend");
        
        // 1. Start Arti
        let mut client = self.tor_client.write().await;
        client.start().await.map_err(|e| crate::AndroidError::NetworkError(e.to_string()))?;
        drop(client); // Release lock
        
        // 2. Start TunStack (Data Plane)
        if self.tun_stack_tx.is_none() {
            info!("Starting userspace TCP/IP stack for Tor...");
            
            let (stack_tx, mut stack_rx) = mpsc::channel::<TunPacket>(1024);
            let packet_to_tun = self.packet_to_tun.clone().ok_or(
                crate::AndroidError::NetworkError("TUN sender not set".into())
            )?;
            
            let tor_client = self.tor_client.clone();
            
            // Spawn stack task
            tokio::spawn(async move {
                // Wrapper for TorClient as BackendProxy
                struct TorProxy(Arc<RwLock<vigilnet_tor::TorClient>>);
                
                #[async_trait::async_trait]
                impl BackendProxy for TorProxy {
                    async fn connect(&self, host: &str, port: u16) -> crate::Result<Box<dyn BackendStream>> {
                        let client = self.0.read().await;
                        client.connect(host, port).await.map(|s| Box::new(s) as Box<dyn BackendStream>)
                    }
                    async fn resolve(&self, host: &str) -> crate::Result<Vec<std::net::IpAddr>> {
                        let client = self.0.read().await;
                        client.resolve(host).await
                    }
                }

                let mut stack = TunStack::new(packet_to_tun, Arc::new(TorProxy(tor_client)));
                info!("TunStack running with Tor egress");
                
                loop {
                    // Calculate wait time or default
                    let wait = tokio::time::Duration::from_millis(50);
                    
                    tokio::select! {
                        pkt = stack_rx.recv() => {
                            if let Some(p) = pkt {
                                stack.poll(Some(p)).await;
                            } else {
                                break; // Sender closed
                            }
                        }
                        _ = tokio::time::sleep(wait) => {
                             stack.poll(None).await;
                        }
                    }
                }
                info!("TunStack stopped");
            });
            
            self.tun_stack_tx = Some(stack_tx);
        }

        info!("Tor backend initialized and bootstrapped");
        Ok(())
    }

    async fn init_i2p(&self) -> crate::Result<()> {
        info!("Initializing I2P backend");
        // TODO: Connect to I2P SAM bridge or start embedded emissary router
        // let sam = SamConnection::connect("127.0.0.1:7656").await?;
        info!("I2P backend initialized (stub)");
        Ok(())
    }

    async fn init_freenet(&self) -> crate::Result<()> {
        info!("Initializing Freenet backend");
        
        let mut node = self.freenet_node.write().await;
        
        if let Err(e) = node.start().await {
            error!("Failed to start Freenet node: {}", e);
            return Err(crate::AndroidError::NetworkError(format!("Freenet start failed: {}", e)));
        }

        info!("Freenet backend initialized and node running");
        Ok(())
    }

    async fn init_wireguard(&self) -> crate::Result<()> {
        info!("Initializing WireGuard backend");
        
        // Example configuration (hardcoded for MVP, in real app this comes from Policy/UI)
        let private_key = "PRIVATE_KEY_PLACEHOLDER"; 
        let peer_key = "PEER_KEY_PLACEHOLDER";
        let endpoint = "1.2.3.4:51820";

        let mut tunnel = self.wg_tunnel.write().await;
        
        // Configure tunnel
        tunnel.set_endpoint(endpoint);
        
        // Initialize boringtun (this spawns valid state)
        if let Err(e) = tunnel.init(private_key, peer_key, None, 25) {
             error!("Failed to init WireGuard tunnel: {}", e);
             return Err(crate::AndroidError::NetworkError(format!("WireGuard init failed: {}", e)));
        }

        // Start tunnel lifecycle (handshake)
        if let Err(e) = tunnel.start().await {
            error!("Failed to start WireGuard handshake: {}", e);
             return Err(crate::AndroidError::NetworkError(format!("WireGuard start failed: {}", e)));
        }

        info!("WireGuard backend initialized and handshake initiated");
        Ok(())
    }

    async fn init_nym(&self) -> crate::Result<()> {
        info!("Initializing Nym mixnet backend");
        
        let mut client = self.nym_client.write().await;
        
        if let Err(e) = client.connect().await {
            error!("Failed to initialize Nym mixnet: {}", e);
            return Err(crate::AndroidError::NetworkError(format!("Nym init failed: {}", e)));
        }

        if let Some(addr) = client.address() {
            info!("Nym backend initialized. Local address: {}", addr);
        }
        
        // Spawn message reception loop in background
        let client_clone = self.nym_client.clone();
        tokio::spawn(async move {
            info!("Starting Nym mixnet message loop");
            loop {
                let mut client = client_clone.write().await;
                match client.wait_for_message().await {
                    Ok((sender, data)) => {
                        info!("Received Mixnet message from {}: {} bytes", sender, data.len());
                        // TODO: Route message to higher-level agents or UI
                    }
                    Err(e) => {
                        error!("Nym message loop error: {}", e);
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                }
            }
        });

        Ok(())
    }

    /// Initialize the mobile agent manager
    pub async fn init_agent_manager(&self, config: crate::agents::MobileAgentConfig) -> crate::Result<()> {
        info!("Initializing mobile agent manager...");
        
        let mut agent_manager = MobileAgentManager::new(config);
        agent_manager.initialize().await?;
        
        let mut am = self.agent_manager.write().await;
        *am = Some(agent_manager);
        
        info!("Mobile agent manager initialized");
        Ok(())
    }

    /// Start all mobile agents
    pub async fn start_agents(&self) -> crate::Result<()> {
        info!("Starting mobile agents...");
        
        let am = self.agent_manager.read().await;
        if let Some(ref mut agent_manager) = *am {
            agent_manager.start().await?;
            info!("Mobile agents started");
        } else {
            warn!("Agent manager not initialized");
        }
        
        Ok(())
    }

    /// Stop all mobile agents
    pub async fn stop_agents(&self) -> crate::Result<()> {
        info!("Stopping mobile agents...");
        
        let am = self.agent_manager.read().await;
        if let Some(ref mut agent_manager) = *am {
            agent_manager.stop().await?;
            info!("Mobile agents stopped");
        }
        
        Ok(())
    }

    /// Get circles service if available
    pub fn get_circles_service(&self) -> Option<Arc<vigilnet_agent_circles::CirclesService>> {
        let am = self.agent_manager.read().await;
        am.as_ref().and_then(|m| m.get_circles_service())
    }

    /// Get mesh agent if available
    pub fn get_mesh_agent(&self) -> Option<Arc<RwLock<vigilnet_agent_mesh::MeshFallback>>> {
        let am = self.agent_manager.read().await;
        am.as_ref().and_then(|m| m.get_mesh_agent())
    }
}

impl Default for NetworkManager {
    fn default() -> Self {
        Self::new()
    }
}
