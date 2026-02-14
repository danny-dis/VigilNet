//! Tor Onion Service (Hidden Service)
//!
//! Allows hosting services reachable via .onion addresses
//! through the VigilNet network.

use tracing::info;

/// Onion service descriptor
#[derive(Debug, Clone)]
pub struct OnionService {
    /// .onion address (v3, 56 chars)
    pub address: String,
    /// Local port to forward to
    pub local_port: u16,
    /// Virtual port (visible to clients)
    pub virtual_port: u16,
    /// Whether the service is running
    pub active: bool,
}

/// Onion service manager
pub struct OnionServiceManager {
    /// Active services
    services: Vec<OnionService>,
}

impl OnionServiceManager {
    /// Create a new manager
    pub fn new() -> Self {
        Self {
            services: Vec::new(),
        }
    }

    /// Create a new onion service
    pub async fn create_service(
        &mut self,
        local_port: u16,
        virtual_port: u16,
    ) -> crate::Result<OnionService> {
        info!("Creating onion service: :{} -> localhost:{}", virtual_port, local_port);

        // TODO: Use arti to create onion service
        // This generates a new keypair and publishes the descriptor
        
        let service = OnionService {
            address: "placeholder.onion".to_string(),
            local_port,
            virtual_port,
            active: true,
        };

        self.services.push(service.clone());
        Ok(service)
    }

    /// Get all services
    pub fn services(&self) -> &[OnionService] {
        &self.services
    }
}

impl Default for OnionServiceManager {
    fn default() -> Self {
        Self::new()
    }
}
