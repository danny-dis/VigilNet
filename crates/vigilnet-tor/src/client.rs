use arti_client::{TorClient as ArtiTorClient, TorClientConfig};
use tor_rtcompat::PreferredRuntime;
use tracing::{info, warn, error};

/// Tor client connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorState {
    /// Not started
    Disconnected,
    /// Bootstrapping (downloading consensus, building circuits)
    Bootstrapping,
    /// Fully connected to the Tor network
    Connected,
    /// Error state
    Error,
}

/// Tor circuit isolation policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationPolicy {
    /// One circuit per destination
    PerDestination,
    /// One circuit per app (Android package)
    PerApp,
    /// Shared circuits for all traffic
    Shared,
}

/// Arti-based Tor client
pub struct TorClient {
    /// The underlying Arti client instance
    client: Option<ArtiTorClient<PreferredRuntime>>,
    /// Current state
    state: TorState,
    /// Bootstrap progress (0-100)
    bootstrap_progress: u8,
    /// SOCKS proxy port (for local apps to connect)
    socks_port: u16,
    /// Circuit isolation policy
    isolation: IsolationPolicy,
    /// Whether to use bridges
    use_bridges: bool,
    /// Configured bridge addresses
    bridges: Vec<String>,
}

impl TorClient {
    /// Create a new Tor client
    pub fn new() -> Self {
        Self {
            client: None,
            state: TorState::Disconnected,
            bootstrap_progress: 0,
            socks_port: 9150, // default Tor SOCKS port (non-standard to avoid conflict)
            isolation: IsolationPolicy::PerDestination,
            use_bridges: false,
            bridges: Vec::new(),
        }
    }

    /// Set the SOCKS port
    pub fn with_socks_port(mut self, port: u16) -> Self {
        self.socks_port = port;
        self
    }

    /// Enable bridge mode with given bridges
    pub fn with_bridges(mut self, bridges: Vec<String>) -> Self {
        self.use_bridges = true;
        self.bridges = bridges;
        self
    }

    /// Set bridges configuration (runtime)
    pub fn set_bridges(&mut self, bridges: Vec<String>) {
        self.use_bridges = !bridges.is_empty();
        self.bridges = bridges;
    }

    /// Set isolation policy
    pub fn with_isolation(mut self, policy: IsolationPolicy) -> Self {
        self.isolation = policy;
        self
    }

    /// Start the Tor client and bootstrap
    pub async fn start(&mut self) -> crate::Result<()> {
        if self.state == TorState::Connected {
            return Ok(());
        }

        self.state = TorState::Bootstrapping;
        info!("Starting Arti Tor client...");

        let mut config_builder = TorClientConfig::builder();
        
        // Configure bridges provided
        if self.use_bridges && !self.bridges.is_empty() {
             info!("Using {} bridge(s)", self.bridges.len());
             
             // Convert bridge lines to BridgeConfig
             let mut bridge_list = Vec::new();
             for bridge_line in &self.bridges {
                 match bridge_line.parse::<arti_client::config::BridgeConfig>() {
                     Ok(b) => bridge_list.push(b),
                     Err(e) => error!("Failed to parse bridge line '{}': {}", bridge_line, e),
                 }
             }
             config_builder.bridges().bridges(bridge_list);

             // Configure Pluggable Transports (obfs4)
             // We need to point to the binary. On Android, this will be in the app's native lib dir or assets.
             // For now, hardcoding a placeholder or checking a known path
             // In a real Android app, we'd extract this binary to data dir.
             let pt_binary_path = std::path::PathBuf::from("/data/local/tmp/obfs4proxy"); // placeholder
             
             let mut transport_config = arti_client::config::TransportConfigBuilder::default();
             transport_config
                 .protocol("obfs4".parse().unwrap())
                 .binary_name(pt_binary_path)
                 .run_on_startup(true);

             if let Err(e) = config_builder.bridges().transports().push(transport_config) {
                 warn!("Failed to add transport config: {}", e);
             }
        }

        let config = config_builder.build().map_err(|e| anyhow::anyhow!("Config error: {}", e))?;

        info!("Bootstrapping connection to Tor network...");
        
        // Create runtime
        let runtime = PreferredRuntime::current()
            .ok_or_else(|| anyhow::anyhow!("Failed to get Tokio runtime"))?;

        // Create and bootstrap client
        let client = ArtiTorClient::create_bootstrapped(runtime, config).await
            .map_err(|e| {
                self.state = TorState::Error;
                anyhow::anyhow!("Bootstrap failed: {}", e)
            })?;

        self.client = Some(client);
        self.bootstrap_progress = 100;
        self.state = TorState::Connected;
        
        info!("Tor client bootstrapped successfully!");
        Ok(())
    }

    /// Stop the Tor client
    pub async fn stop(&mut self) {
        info!("Stopping Tor client");
        // Drop client to close connections
        self.client = None;
        self.state = TorState::Disconnected;
        self.bootstrap_progress = 0;
    }

    /// Get current state
    pub fn state(&self) -> TorState {
        self.state
    }

    /// Get bootstrap progress (0-100)
    pub fn bootstrap_progress(&self) -> u8 {
        self.bootstrap_progress
    }

    /// Create an anonymous TCP stream through Tor
    pub async fn connect(&self, host: &str, port: u16) -> crate::Result<arti_client::DataStream> {
        let client = self.client.as_ref().ok_or(crate::TorError::NotInitialized)?;
        
        if self.state != TorState::Connected {
            return Err(crate::TorError::NotInitialized);
        }
        
        info!("Opening Tor stream to {}:{}", host, port);
        
        // Connect using default isolation preferences for now
        let stream = client.connect((host, port)).await
            .map_err(|e| anyhow::anyhow!("Stream connection failed: {}", e))?;
            
        Ok(stream)
    }

    /// Resolve a hostname through Tor
    pub async fn resolve(&self, hostname: &str) -> crate::Result<Vec<std::net::IpAddr>> {
        let client = self.client.as_ref().ok_or(crate::TorError::NotInitialized)?;

        if self.state != TorState::Connected {
            return Err(crate::TorError::NotInitialized);
        }

        info!("Resolving {} through Tor", hostname);
        
        let ips = client.resolve(hostname).await
             .map_err(|e| anyhow::anyhow!("Resolution failed: {}", e))?;
             
        Ok(ips)
    }
}

impl Default for TorClient {
    fn default() -> Self {
        Self::new()
    }
}
