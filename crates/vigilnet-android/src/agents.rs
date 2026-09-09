//! Agent Support for Android
//!
//! Provides integration for running VigilNet agents on Android mobile devices.
//! Supports mesh fallback, circles, research agents with E2EE transport.

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};

use vigilnet_agent_core::Agent;
use vigilnet_agent_transport::MobileE2ETransport;

/// Configuration for mobile agents
#[derive(Debug, Clone)]
pub struct MobileAgentConfig {
    pub enable_mesh: bool,
    pub enable_circles: bool,
    pub enable_research: bool,
    pub storage_path: Option<std::path::PathBuf>,
}

impl Default for MobileAgentConfig {
    fn default() -> Self {
        Self {
            enable_mesh: true,
            enable_circles: true,
            enable_research: false,
            storage_path: None,
        }
    }
}

/// Mobile agent manager - coordinates all agents on Android
pub struct MobileAgentManager {
    config: MobileAgentConfig,
    mesh_agent: Option<Arc<RwLock<vigilnet_agent_mesh::MeshFallback>>>,
    circles_service: Option<Arc<vigilnet_agent_circles::CirclesService>>,
    research_agent: Option<Arc<RwLock<vigilnet_agent_research::ResearchAgent>>>,
    e2e_transport: Arc<RwLock<MobileE2ETransport>>,
    running: bool,
}

impl MobileAgentManager {
    /// Create a new mobile agent manager
    pub fn new(config: MobileAgentConfig) -> Self {
        let e2e_transport = MobileE2ETransport::new();
        
        Self {
            config,
            mesh_agent: None,
            circles_service: None,
            research_agent: None,
            e2e_transport: Arc::new(RwLock::new(e2e_transport)),
            running: false,
        }
    }

    /// Set the storage path
    pub fn set_storage_path(&mut self, path: std::path::PathBuf) {
        self.config.storage_path = Some(path);
    }

    /// Initialize all enabled agents
    pub async fn initialize(&mut self) -> crate::Result<()> {
        info!("Initializing mobile agents...");

        // Initialize E2E Transport with peer ID
        {
            let mut transport = self.e2e_transport.write().await;
            transport.initialize().await?;
        }

        // Initialize Mesh Agent
        if self.config.enable_mesh {
            info!("Initializing Mesh Agent...");
            let mesh_config = vigilnet_agent_mesh::MeshFallbackConfig::default();
            match vigilnet_agent_mesh::MeshFallback::new(mesh_config) {
                Ok(mesh) => {
                    self.mesh_agent = Some(Arc::new(RwLock::new(mesh)));
                    info!("Mesh Agent initialized");
                }
                Err(e) => {
                    error!("Failed to initialize Mesh Agent: {}", e);
                    return Err(crate::AndroidError::CoreError(
                        vigilnet_core::Error::Other(format!("Mesh init failed: {}", e))
                    ));
                }
            }
        }

        // Initialize Circles Service
        if self.config.enable_circles {
            info!("Initializing Circles Service...");
            let circles = Arc::new(vigilnet_agent_circles::CirclesService::new());
            self.circles_service = Some(circles);
            info!("Circles Service initialized");
        }

        // Initialize Research Agent
        if self.config.enable_research {
            info!("Initializing Research Agent...");
            match vigilnet_agent_research::ResearchAgent::new().await {
                Ok(agent) => {
                    self.research_agent = Some(Arc::new(RwLock::new(agent)));
                    info!("Research Agent initialized");
                }
                Err(e) => {
                    warn!("Failed to initialize Research Agent: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Start all agents
    pub async fn start(&mut self) -> crate::Result<()> {
        if self.running {
            return Ok(());
        }

        info!("Starting mobile agents...");

        // Start Mesh Agent
        if let Some(mesh) = &self.mesh_agent {
            let mesh = mesh.clone();
            let e2e = self.e2e_transport.clone();
            tokio::spawn(async move {
                let mesh = mesh.read().await;
                if let Err(e) = mesh.run().await {
                    error!("Mesh Agent runtime error: {}", e);
                }
            });
            info!("Mesh Agent started");
        }

        // Start Research Agent if enabled
        if let Some(research) = &self.research_agent {
            let research = research.clone();
            tokio::spawn(async move {
                let research = research.read().await;
                if let Err(e) = research.start().await {
                    error!("Research Agent error: {}", e);
                }
            });
            info!("Research Agent started");
        }

        self.running = true;
        info!("All mobile agents started");
        Ok(())
    }

    /// Stop all agents
    pub async fn stop(&mut self) -> crate::Result<()> {
        if !self.running {
            return Ok(());
        }

        info!("Stopping mobile agents...");

        // Stop Mesh Agent
        if let Some(mesh) = &self.mesh_agent {
            let mesh = mesh.clone();
            let mut m = mesh.write().await;
            if let Err(e) = m.stop().await {
                warn!("Error stopping Mesh Agent: {}", e);
            }
        }

        // Stop Research Agent
        if let Some(research) = &self.research_agent {
            let research = research.clone();
            let mut r = research.write().await;
            if let Err(e) = r.stop().await {
                warn!("Error stopping Research Agent: {}", e);
            }
        }

        self.running = false;
        info!("All mobile agents stopped");
        Ok(())
    }

    /// Get the E2E transport for agents
    pub fn get_e2e_transport(&self) -> Arc<RwLock<MobileE2ETransport>> {
        self.e2e_transport.clone()
    }

    /// Get circles service
    pub fn get_circles_service(&self) -> Option<Arc<vigilnet_agent_circles::CirclesService>> {
        self.circles_service.clone()
    }

    /// Get mesh agent
    pub fn get_mesh_agent(&self) -> Option<Arc<RwLock<vigilnet_agent_mesh::MeshFallback>>> {
        self.mesh_agent.clone()
    }

    /// Check if agents are running
    pub fn is_running(&self) -> bool {
        self.running
    }
}

impl Default for MobileAgentManager {
    fn default() -> Self {
        Self::new(MobileAgentConfig::default())
    }
}
