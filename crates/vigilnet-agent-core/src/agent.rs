//! Agent identity and information for VigilNet

use libp2p::PeerId;
use serde::{Deserialize, Serialize};

/// Agent identity based on PeerId
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub PeerId);

impl AgentId {
    pub fn new(peer_id: PeerId) -> Self {
        Self(peer_id)
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, AgentError> {
        PeerId::from_bytes(bytes)
            .map(AgentId)
            .map_err(|e| AgentError::InvalidPeerId(e.to_string()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let bytes = self.0.as_bytes();
        let mut result = [0u8; 32];
        result.copy_from_slice(bytes);
        result
    }
}

impl From<PeerId> for AgentId {
    fn from(peer_id: PeerId) -> Self {
        Self(peer_id)
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AgentId({})", self.0)
    }
}

/// Agent information and capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub id: AgentId,
    pub name: String,
    pub capabilities: Vec<String>,
    pub model_type: String,
    pub trust_score: f64,
    pub latency_ns: u64,
    pub is_online: bool,
    pub last_seen: i64,
    pub connected_peers: usize,
}

impl AgentInfo {
    pub fn new(
        id: AgentId,
        name: String,
        capabilities: Vec<String>,
        model_type: String,
    ) -> Self {
        Self {
            id,
            name,
            capabilities,
            model_type,
            trust_score: 1.0,
            latency_ns: 0,
            is_online: true,
            last_seen: chrono::Utc::now().timestamp(),
            connected_peers: 0,
        }
    }

    pub fn update_latency(&mut self, latency_ns: u64) {
        self.latency_ns = latency_ns;
        self.last_seen = chrono::Utc::now().timestamp();
    }

    pub fn set_online(&mut self, online: bool) {
        self.is_online = online;
        if online {
            self.last_seen = chrono::Utc::now().timestamp();
        }
    }

    pub fn update_trust(&mut self, delta: f64) {
        self.trust_score = (self.trust_score + delta).clamp(0.0, 1.0);
    }

    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|c| c.eq_ignore_ascii_case(capability))
    }
}

/// Agent error types
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("Invalid peer ID: {0}")]
    InvalidPeerId(String),

    #[error("Agent not found: {0}")]
    NotFound(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
}

pub type Result<T> = std::result::Result<T, AgentError>;
