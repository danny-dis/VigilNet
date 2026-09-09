//! Tor Onion Service (Hidden Service)
//!
//! Allows hosting services reachable via .onion addresses
//! through the VigilNet network.

use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionService {
    pub address: String,
    pub private_key: Vec<u8>,
    pub local_port: u16,
    pub virtual_port: u16,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionServiceConfig {
    pub local_port: u16,
    pub virtual_port: u16,
    pub ephemeral: bool,
    pub max_connections: u32,
}

impl Default for OnionServiceConfig {
    fn default() -> Self {
        Self {
            local_port: 8080,
            virtual_port: 80,
            ephemeral: false,
            max_connections: 100,
        }
    }
}

pub struct OnionServiceManager {
    services: Vec<OnionService>,
    config: OnionServiceConfig,
}

impl OnionServiceManager {
    pub fn new() -> Self {
        Self {
            services: Vec::new(),
            config: OnionServiceConfig::default(),
        }
    }

    pub fn with_config(mut self, config: OnionServiceConfig) -> Self {
        self.config = config;
        self
    }

    pub async fn create_service(
        &mut self,
        local_port: u16,
        virtual_port: u16,
    ) -> crate::Result<OnionService> {
        info!("Creating onion service: :{} -> localhost:{}", virtual_port, local_port);

        let keypair = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public_key = x25519_dalek::PublicKey::from(&keypair);
        
        let address = format!("{}.onion", base32::encode(base32::Alphabet::Rfc4648 { padding: false }, public_key.as_bytes()));

        let service = OnionService {
            address,
            private_key: keypair.to_bytes().to_vec(),
            local_port,
            virtual_port,
            active: true,
        };

        self.services.push(service.clone());
        info!("Onion service created: {}", service.address);
        Ok(service)
    }

    pub fn services(&self) -> &[OnionService] {
        &self.services
    }

    pub fn get_service(&self, address: &str) -> Option<&OnionService> {
        self.services.iter().find(|s| s.address == address)
    }

    pub fn remove_service(&mut self, address: &str) -> bool {
        if let Some(pos) = self.services.iter().position(|s| s.address == address) {
            self.services.remove(pos);
            true
        } else {
            false
        }
    }
}

impl Default for OnionServiceManager {
    fn default() -> Self {
        Self::new()
    }
}
