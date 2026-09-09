use arti_client::{TorClient as ArtiTorClient, TorClientConfig};
use tor_rtcompat::PreferredRuntime;
use tracing::{info, warn, error};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorState {
    Disconnected,
    Bootstrapping,
    Connected,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationPolicy {
    PerDestination,
    PerApp,
    Shared,
}

pub struct TorClient {
    client: Option<ArtiTorClient<PreferredRuntime>>,
    state: TorState,
    bootstrap_progress: u8,
    socks_port: u16,
    isolation: IsolationPolicy,
    use_bridges: bool,
    bridges: Vec<String>,
}

impl TorClient {
    pub fn new() -> Self {
        Self {
            client: None,
            state: TorState::Disconnected,
            bootstrap_progress: 0,
            socks_port: 9150,
            isolation: IsolationPolicy::PerDestination,
            use_bridges: false,
            bridges: Vec::new(),
        }
    }

    pub fn with_socks_port(mut self, port: u16) -> Self {
        self.socks_port = port;
        self
    }

    pub fn with_bridges(mut self, bridges: Vec<String>) -> Self {
        self.use_bridges = true;
        self.bridges = bridges;
        self
    }

    pub fn set_bridges(&mut self, bridges: Vec<String>) {
        self.use_bridges = !bridges.is_empty();
        self.bridges = bridges;
    }

    pub fn with_isolation(mut self, policy: IsolationPolicy) -> Self {
        self.isolation = policy;
        self
    }

    pub async fn start(&mut self) -> crate::Result<()> {
        if self.state == TorState::Connected {
            return Ok(());
        }

        self.state = TorState::Bootstrapping;
        info!("Starting Arti Tor client...");

        let mut config_builder = TorClientConfig::builder();
        
        if self.use_bridges && !self.bridges.is_empty() {
             info!("Using {} bridge(s)", self.bridges.len());
              
             let mut bridge_list = Vec::new();
             for bridge_line in &self.bridges {
                 match bridge_line.parse::<arti_client::config::BridgeConfig>() {
                     Ok(b) => bridge_list.push(b),
                     Err(e) => error!("Failed to parse bridge line '{}': {}", bridge_line, e),
                 }
             }
             config_builder.bridges().bridges(bridge_list);
        }

        let config = config_builder.build().map_err(|e| anyhow::anyhow!("Config error: {}", e))?;

        info!("Bootstrapping connection to Tor network...");
        
        let runtime = PreferredRuntime::current()
            .ok_or_else(|| anyhow::anyhow!("Failed to get Tokio runtime"))?;

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

    pub async fn stop(&mut self) {
        info!("Stopping Tor client");
        self.client = None;
        self.state = TorState::Disconnected;
        self.bootstrap_progress = 0;
    }

    pub fn state(&self) -> TorState {
        self.state
    }

    pub fn bootstrap_progress(&self) -> u8 {
        self.bootstrap_progress
    }

    pub async fn connect(&self, host: &str, port: u16) -> crate::Result<arti_client::DataStream> {
        let client = self.client.as_ref().ok_or(crate::TorError::NotInitialized)?;
        
        if self.state != TorState::Connected {
            return Err(crate::TorError::NotInitialized);
        }
        
        info!("Opening Tor stream to {}:{}", host, port);
        
        let stream = client.connect((host, port)).await
            .map_err(|e| anyhow::anyhow!("Stream connection failed: {}", e))?;
            
        Ok(stream)
    }

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
