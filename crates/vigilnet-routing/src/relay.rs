//! Relay node logic

use std::collections::HashSet;
use vigilnet_crypto::onion::{RelayCell, RelayCommand, CircuitCell};

/// Exit policy for a relay
#[derive(Debug, Clone)]
pub struct ExitPolicy {
    /// Allowed ports (empty = all allowed)
    pub allowed_ports: HashSet<u16>,
    /// Blocked ports
    pub blocked_ports: HashSet<u16>,
    /// Whether to allow all by default
    pub default_allow: bool,
}

impl ExitPolicy {
    /// Create a permissive exit policy
    pub fn allow_all() -> Self {
        Self {
            allowed_ports: HashSet::new(),
            blocked_ports: HashSet::new(),
            default_allow: true,
        }
    }

    /// Create a restrictive exit policy (common ports only)
    pub fn common_ports() -> Self {
        let mut policy = Self {
            allowed_ports: HashSet::new(),
            blocked_ports: HashSet::new(),
            default_allow: false,
        };
        // HTTP, HTTPS, SSH, DNS
        policy.allowed_ports.insert(80);
        policy.allowed_ports.insert(443);
        policy.allowed_ports.insert(22);
        policy.allowed_ports.insert(53);
        policy
    }

    /// Check if a port is allowed
    pub fn is_port_allowed(&self, port: u16) -> bool {
        if self.blocked_ports.contains(&port) {
            return false;
        }
        if !self.allowed_ports.is_empty() && !self.allowed_ports.contains(&port) {
            return false;
        }
        self.default_allow || self.allowed_ports.contains(&port)
    }
}

impl Default for ExitPolicy {
    fn default() -> Self {
        Self::common_ports()
    }
}

/// A relay node's configuration
pub struct Relay {
    /// Our peer ID
    pub peer_id: [u8; 32],
    /// Whether we act as a relay
    pub is_relay: bool,
    /// Whether we act as an exit
    pub is_exit: bool,
    /// Exit policy (if exit)
    pub exit_policy: ExitPolicy,
    /// Bandwidth limit in bytes/sec (0 = unlimited)
    pub bandwidth_limit: u64,
}

impl Relay {
    /// Create a new relay configuration
    pub fn new(peer_id: [u8; 32]) -> Self {
        Self {
            peer_id,
            is_relay: true,
            is_exit: false,
            exit_policy: ExitPolicy::default(),
            bandwidth_limit: 0,
        }
    }

    /// Configure as exit node
    pub fn as_exit(mut self, policy: ExitPolicy) -> Self {
        self.is_exit = true;
        self.exit_policy = policy;
        self
    }

    /// Set bandwidth limit
    pub fn with_bandwidth_limit(mut self, bytes_per_sec: u64) -> Self {
        self.bandwidth_limit = bytes_per_sec;
        self
    }

    /// Check if traffic to a port is allowed
    pub fn can_exit_to(&self, port: u16) -> bool {
        self.is_exit && self.exit_policy.is_port_allowed(port)
    }

    /// Handle an incoming CREATE cell
    ///
    /// Performs the relay side of the handshake:
    /// 1. Uses our static identity key to complete DH with their ephemeral key
    /// 2. Generates our ephemeral response key
    /// 3. Returns the CREATED cell and the shared session key
    pub fn handle_create(
        &self,
        create_cell: &vigilnet_crypto::onion::CreateCell,
        our_static_secret: &vigilnet_crypto::keys::StaticSecret,
    ) -> crate::Result<(vigilnet_crypto::onion::CreatedCell, vigilnet_crypto::SessionKey)> {
        use vigilnet_crypto::SessionKey;
        use vigilnet_crypto::onion::CreatedCell;
        
        // 1. Perform DH exchange (Static-Ephemeral)
        // In a real implementation we might use a dedicated onion key distinct from identity,
        // but for now we use the node's static identity key (converted to Curve25519)
        // NOTE: Ed25519 keys cannot be directly converted to X25519 for DH safely in all cases.
        // We should really have a separate X25519 static key for the node. 
        // For this Prototype, we will assume `our_static_secret` is a dedicated X25519 key managed by the node.
        
        let peer_public = x25519_dalek::PublicKey::from(create_cell.dh_public);
        let shared_secret = SessionKey::exchange(our_static_secret, &peer_public);
        
        // 2. Generate our ephemeral keypair
        let (ephemeral_secret, ephemeral_public) = SessionKey::generate_ephemeral();
        
        // 3. Derive HTTP response key (in full Tor spec there are multiple keys derived from shared secret)
        // Here we just use the shared secret as the session key.
        
        let created_cell = CreatedCell::new(
            create_cell.circuit_id,
            *ephemeral_public.as_bytes(),
        );
        
        Ok((created_cell, shared_secret))
    }

    /// Handle an incoming RELAY cell
    ///
    /// Decrypts one layer of encryption using the session key.
    pub fn handle_relay(
        &self,
        encrypted_data: &[u8],
        session_key: &vigilnet_crypto::SessionKey,
    ) -> crate::Result<Option<RelayCell>> {
        let decrypted = self.decrypt_cell(encrypted_data, session_key)?;
        
        match RelayCell::from_bytes(&decrypted) {
            Ok(cell) => Ok(Some(cell)),
            Err(_) => Ok(None),
        }
    }
    
    /// Process a relay cell command and generate response
    pub fn process_relay_command(
        &self,
        relay_cell: &RelayCell,
        session_key: &vigilnet_crypto::SessionKey,
    ) -> crate::Result<Option<CircuitCell>> {
        match relay_cell.command {
            RelayCommand::Data => {
                Ok(None)
            }
            RelayCommand::Begin => {
                Ok(None)
            }
            RelayCommand::End => {
                Ok(None)
            }
            RelayCommand::Extend => {
                Ok(None)
            }
            RelayCommand::Extended => {
                Ok(None)
            }
            RelayCommand::Drop => {
                Ok(None)
            }
            _ => Ok(None),
        }
    }
    
    /// Decrypt a Relay cell payload
    pub fn decrypt_cell(
        &self,
        encrypted_data: &[u8],
        session_key: &vigilnet_crypto::SessionKey,
    ) -> crate::Result<Vec<u8>> {
        vigilnet_crypto::aead::decrypt(session_key.as_bytes(), encrypted_data)
            .map_err(|e| crate::RoutingError::Crypto(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_policy() {
        let policy = ExitPolicy::common_ports();
        assert!(policy.is_port_allowed(80));
        assert!(policy.is_port_allowed(443));
        assert!(!policy.is_port_allowed(25)); // SMTP blocked
    }

    #[test]
    fn test_relay_exit() {
        let relay = Relay::new([1u8; 32]).as_exit(ExitPolicy::common_ports());
        assert!(relay.can_exit_to(80));
        assert!(!relay.can_exit_to(25));
    }
}
