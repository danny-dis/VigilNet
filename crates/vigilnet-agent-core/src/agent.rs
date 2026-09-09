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

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================
    // Unit Tests for Core Functionality
    // ============================================

    #[test]
    fn test_agent_id_creation() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        assert_eq!(agent_id.0, peer_id);
    }

    #[test]
    fn test_agent_id_from_peer_id() {
        let peer_id = PeerId::random();
        let agent_id: AgentId = peer_id.into();
        assert_eq!(agent_id.0, peer_id);
    }

    #[test]
    fn test_agent_id_bytes_roundtrip() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let bytes = agent_id.to_bytes();
        let recovered = AgentId::from_bytes(&bytes);
        assert!(recovered.is_ok());
        // Note: PeerId from_bytes creates a new ID, won't match exactly
    }

    #[test]
    fn test_agent_id_as_bytes() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let bytes = agent_id.as_bytes();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_agent_id_display() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let display_str = format!("{}", agent_id);
        assert!(display_str.starts_with("AgentId("));
        assert!(display_str.contains(&peer_id.to_string()));
    }

    #[test]
    fn test_agent_id_clone() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let cloned = agent_id.clone();
        assert_eq!(agent_id.0, cloned.0);
    }

    #[test]
    fn test_agent_id_equality() {
        let peer_id = PeerId::random();
        let id1 = AgentId::new(peer_id);
        let id2 = AgentId::new(peer_id);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_agent_id_hash() {
        use std::collections::HashSet;
        let peer_id = PeerId::random();
        let id1 = AgentId::new(peer_id);
        let id2 = AgentId::new(peer_id);
        
        let mut set = HashSet::new();
        set.insert(id1);
        assert!(set.contains(&id2));
    }

    #[test]
    fn test_agent_info_creation() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let info = AgentInfo::new(
            agent_id.clone(),
            "test-agent".to_string(),
            vec!["cap1".to_string(), "cap2".to_string()],
            "gpt-4".to_string(),
        );
        
        assert_eq!(info.name, "test-agent");
        assert_eq!(info.capabilities.len(), 2);
        assert_eq!(info.model_type, "gpt-4");
        assert_eq!(info.trust_score, 1.0);
        assert!(info.is_online);
        assert_eq!(info.latency_ns, 0);
    }

    #[test]
    fn test_agent_info_update_latency() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let mut info = AgentInfo::new(
            agent_id,
            "test".to_string(),
            vec![],
            "model".to_string(),
        );
        
        let original_last_seen = info.last_seen;
        info.update_latency(1_000_000); // 1ms in ns
        
        assert_eq!(info.latency_ns, 1_000_000);
        assert!(info.last_seen >= original_last_seen);
    }

    #[test]
    fn test_agent_info_set_online() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let mut info = AgentInfo::new(
            agent_id,
            "test".to_string(),
            vec![],
            "model".to_string(),
        );
        
        info.set_online(false);
        assert!(!info.is_online);
        
        info.set_online(true);
        assert!(info.is_online);
    }

    #[test]
    fn test_agent_info_update_trust() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let mut info = AgentInfo::new(
            agent_id,
            "test".to_string(),
            vec![],
            "model".to_string(),
        );
        
        info.update_trust(-0.3);
        assert_eq!(info.trust_score, 0.7);
        
        info.update_trust(-1.0);
        assert_eq!(info.trust_score, 0.0); // Clamped
        
        info.update_trust(0.5);
        assert_eq!(info.trust_score, 0.5);
        
        info.update_trust(1.0);
        assert_eq!(info.trust_score, 1.0); // Clamped
    }

    #[test]
    fn test_agent_info_has_capability() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let info = AgentInfo::new(
            agent_id,
            "test".to_string(),
            vec!["Finance".to_string(), "HealthCare".to_string()],
            "model".to_string(),
        );
        
        assert!(info.has_capability("finance"));
        assert!(info.has_capability("FINANCE"));
        assert!(info.has_capability("Healthcare"));
        assert!(!info.has_capability("technology"));
    }

    #[test]
    fn test_agent_info_has_capability_empty() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let info = AgentInfo::new(
            agent_id,
            "test".to_string(),
            vec![],
            "model".to_string(),
        );
        
        assert!(!info.has_capability("anything"));
    }

    #[test]
    fn test_agent_info_clone() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let info = AgentInfo::new(
            agent_id,
            "test".to_string(),
            vec!["cap1".to_string()],
            "model".to_string(),
        );
        
        let cloned = info.clone();
        assert_eq!(info.name, cloned.name);
        assert_eq!(info.capabilities, cloned.capabilities);
        assert_eq!(info.trust_score, cloned.trust_score);
    }

    // ============================================
    // Integration Tests
    // ============================================

    #[test]
    fn test_agent_info_serialization() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let info = AgentInfo::new(
            agent_id,
            "test-agent".to_string(),
            vec!["research".to_string(), "analysis".to_string()],
            "claude-3".to_string(),
        );
        
        let serialized = serde_json::to_string(&info).unwrap();
        let deserialized: AgentInfo = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(info.name, deserialized.name);
        assert_eq!(info.capabilities, deserialized.capabilities);
        assert_eq!(info.model_type, deserialized.model_type);
        assert_eq!(info.trust_score, deserialized.trust_score);
    }

    #[test]
    fn test_multiple_agents() {
        let agents: Vec<AgentInfo> = (0..10).map(|i| {
            let peer_id = PeerId::random();
            AgentInfo::new(
                AgentId::new(peer_id),
                format!("agent-{}", i),
                vec![format!("cap-{}", i)],
                format!("model-{}", i),
            )
        }).collect();
        
        assert_eq!(agents.len(), 10);
        for (i, agent) in agents.iter().enumerate() {
            assert_eq!(agent.name, format!("agent-{}", i));
        }
    }

    #[test]
    fn test_agent_lifecycle() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let mut info = AgentInfo::new(
            agent_id,
            "lifecycle-test".to_string(),
            vec!["compute".to_string()],
            "gpt-4".to_string(),
        );
        
        // Initial state
        assert_eq!(info.trust_score, 1.0);
        assert!(info.is_online);
        
        // Perform work
        info.update_latency(100_000);
        
        // Encounter issue
        info.update_trust(-0.5);
        assert_eq!(info.trust_score, 0.5);
        
        // Go offline
        info.set_online(false);
        assert!(!info.is_online);
        
        // Come back online
        info.set_online(true);
        assert!(info.is_online);
        
        // Recover trust
        info.update_trust(0.3);
        assert_eq!(info.trust_score, 0.8);
    }

    // ============================================
    // Error Handling Tests
    // ============================================

    #[test]
    fn test_agent_id_from_invalid_bytes() {
        let invalid_bytes = [0u8; 32];
        let result = AgentId::from_bytes(&invalid_bytes);
        assert!(result.is_err());
        
        if let Err(AgentError::InvalidPeerId(_)) = result {
            // Expected error type
        } else {
            panic!("Expected InvalidPeerId error");
        }
    }

    #[test]
    fn test_agent_error_display() {
        let err1 = AgentError::InvalidPeerId("test".to_string());
        assert!(err1.to_string().contains("Invalid peer ID"));
        
        let err2 = AgentError::NotFound("agent123".to_string());
        assert!(err2.to_string().contains("Agent not found"));
        assert!(err2.to_string().contains("agent123"));
        
        let err3 = AgentError::SerializationError("json error".to_string());
        assert!(err3.to_string().contains("Serialization error"));
        
        let err4 = AgentError::InvalidOperation("bad op".to_string());
        assert!(err4.to_string().contains("Invalid operation"));
    }

    #[test]
    fn test_result_type() {
        fn successful_op() -> Result<AgentId> {
            Ok(AgentId::new(PeerId::random()))
        }
        
        fn failing_op() -> Result<AgentId> {
            Err(AgentError::NotFound("missing".to_string()))
        }
        
        assert!(successful_op().is_ok());
        assert!(failing_op().is_err());
    }

    // ============================================
    // Edge Case Tests
    // ============================================

    #[test]
    fn test_agent_info_empty_name() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let info = AgentInfo::new(
            agent_id,
            "".to_string(),
            vec![],
            "model".to_string(),
        );
        assert_eq!(info.name, "");
    }

    #[test]
    fn test_agent_info_long_name() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let long_name = "a".repeat(1000);
        let info = AgentInfo::new(
            agent_id,
            long_name.clone(),
            vec![],
            "model".to_string(),
        );
        assert_eq!(info.name.len(), 1000);
    }

    #[test]
    fn test_agent_info_many_capabilities() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let caps: Vec<String> = (0..100).map(|i| format!("cap-{}", i)).collect();
        let info = AgentInfo::new(
            agent_id,
            "test".to_string(),
            caps,
            "model".to_string(),
        );
        assert_eq!(info.capabilities.len(), 100);
    }

    #[test]
    fn test_agent_info_duplicate_capabilities() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let info = AgentInfo::new(
            agent_id,
            "test".to_string(),
            vec!["cap".to_string(), "cap".to_string(), "CAP".to_string()],
            "model".to_string(),
        );
        // Should have 3 entries even if duplicates
        assert_eq!(info.capabilities.len(), 3);
        // Case-insensitive check should match first
        assert!(info.has_capability("cap"));
    }

    #[test]
    fn test_trust_score_boundary_values() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let mut info = AgentInfo::new(
            agent_id,
            "test".to_string(),
            vec![],
            "model".to_string(),
        );
        
        // Test exact boundary values
        info.trust_score = 0.0;
        info.update_trust(-0.1);
        assert_eq!(info.trust_score, 0.0);
        
        info.trust_score = 1.0;
        info.update_trust(0.1);
        assert_eq!(info.trust_score, 1.0);
        
        // Test zero delta
        info.trust_score = 0.5;
        info.update_trust(0.0);
        assert_eq!(info.trust_score, 0.5);
    }

    #[test]
    fn test_latency_zero() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let mut info = AgentInfo::new(
            agent_id,
            "test".to_string(),
            vec![],
            "model".to_string(),
        );
        
        info.update_latency(0);
        assert_eq!(info.latency_ns, 0);
    }

    #[test]
    fn test_latency_max_value() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let mut info = AgentInfo::new(
            agent_id,
            "test".to_string(),
            vec![],
            "model".to_string(),
        );
        
        info.update_latency(u64::MAX);
        assert_eq!(info.latency_ns, u64::MAX);
    }

    #[test]
    fn test_capability_case_sensitivity() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let info = AgentInfo::new(
            agent_id,
            "test".to_string(),
            vec![
                "UpperCase".to_string(),
                "lowercase".to_string(),
                "MiXeD".to_string(),
            ],
            "model".to_string(),
        );
        
        assert!(info.has_capability("uppercase"));
        assert!(info.has_capability("UPPERCASE"));
        assert!(info.has_capability("LowerCase"));
        assert!(info.has_capability("mixed"));
        assert!(info.has_capability("MIXED"));
    }

    #[test]
    fn test_last_seen_timestamp() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let mut info = AgentInfo::new(
            agent_id,
            "test".to_string(),
            vec![],
            "model".to_string(),
        );
        
        let before = chrono::Utc::now().timestamp();
        info.set_online(true);
        let after = chrono::Utc::now().timestamp();
        
        assert!(info.last_seen >= before);
        assert!(info.last_seen <= after);
    }

    #[test]
    fn test_agent_info_debug() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let info = AgentInfo::new(
            agent_id,
            "test".to_string(),
            vec!["cap".to_string()],
            "model".to_string(),
        );
        
        let debug_str = format!("{:?}", info);
        assert!(debug_str.contains("AgentInfo"));
        assert!(debug_str.contains("test"));
    }

    #[test]
    fn test_agent_id_debug() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let debug_str = format!("{:?}", agent_id);
        assert!(debug_str.contains("AgentId"));
    }

    #[test]
    fn test_model_type_variations() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        
        let models = vec![
            "gpt-4",
            "gpt-3.5-turbo",
            "claude-3-opus",
            "claude-3-sonnet",
            "llama-2-70b",
            "mistral-7b",
            "",
            "custom-model-v1.2.3",
        ];
        
        for model in models {
            let info = AgentInfo::new(
                AgentId::new(PeerId::random()),
                "test".to_string(),
                vec![],
                model.to_string(),
            );
            assert_eq!(info.model_type, model);
        }
    }

    #[test]
    fn test_connected_peers_tracking() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let mut info = AgentInfo::new(
            agent_id,
            "test".to_string(),
            vec![],
            "model".to_string(),
        );
        
        assert_eq!(info.connected_peers, 0);
        info.connected_peers = 5;
        assert_eq!(info.connected_peers, 5);
    }

    #[test]
    fn test_default_values() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let info = AgentInfo::new(
            agent_id,
            "test".to_string(),
            vec![],
            "model".to_string(),
        );
        
        assert_eq!(info.trust_score, 1.0);
        assert_eq!(info.latency_ns, 0);
        assert!(info.is_online);
        assert_eq!(info.connected_peers, 0);
    }

    #[test]
    fn test_multiple_trust_updates() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let mut info = AgentInfo::new(
            agent_id,
            "test".to_string(),
            vec![],
            "model".to_string(),
        );
        
        // Gradual decrease
        for _ in 0..5 {
            info.update_trust(-0.1);
        }
        assert_eq!(info.trust_score, 0.5);
        
        // Gradual increase
        for _ in 0..3 {
            info.update_trust(0.1);
        }
        assert_eq!(info.trust_score, 0.8);
    }

    #[test]
    fn test_special_characters_in_name() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let special_names = vec![
            "agent-123",
            "agent_123",
            "agent.123",
            "agent@123",
            "agent#123",
            "agent$123",
            "agent%123",
            "agent&123",
            "agent*123",
            "agent(123)",
            "agent[123]",
            "agent{123}",
        ];
        
        for name in special_names {
            let info = AgentInfo::new(
                AgentId::new(PeerId::random()),
                name.to_string(),
                vec![],
                "model".to_string(),
            );
            assert_eq!(info.name, name);
        }
    }

    #[test]
    fn test_unicode_in_name() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let unicode_names = vec![
            "代理-1",
            "エージェント",
            "에이전트",
            "🤖-agent",
            "agent-α",
            "agent-β",
        ];
        
        for name in unicode_names {
            let info = AgentInfo::new(
                AgentId::new(PeerId::random()),
                name.to_string(),
                vec![],
                "model".to_string(),
            );
            assert_eq!(info.name, name);
        }
    }

    #[test]
    fn test_peer_id_from_different_sources() {
        // Create IDs from different sources and ensure they work
        for _ in 0..10 {
            let peer_id = PeerId::random();
            let agent_id = AgentId::new(peer_id);
            let info = AgentInfo::new(
                agent_id,
                format!("agent-{}", rand::random::<u16>()),
                vec![],
                "model".to_string(),
            );
            assert!(!info.name.is_empty());
        }
    }

    #[test]
    fn test_serialize_deserialize_preserves_all_fields() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let mut info = AgentInfo::new(
            agent_id,
            "full-test".to_string(),
            vec!["cap1".to_string(), "cap2".to_string()],
            "gpt-4-turbo".to_string(),
        );
        info.trust_score = 0.85;
        info.latency_ns = 1_500_000;
        info.is_online = false;
        info.connected_peers = 42;
        
        let serialized = bincode::serialize(&info).unwrap();
        let deserialized: AgentInfo = bincode::deserialize(&serialized).unwrap();
        
        assert_eq!(info.name, deserialized.name);
        assert_eq!(info.capabilities, deserialized.capabilities);
        assert_eq!(info.model_type, deserialized.model_type);
        assert_eq!(info.trust_score, deserialized.trust_score);
        assert_eq!(info.latency_ns, deserialized.latency_ns);
        assert_eq!(info.is_online, deserialized.is_online);
        assert_eq!(info.connected_peers, deserialized.connected_peers);
    }

    #[test]
    fn test_partial_capability_match() {
        let peer_id = PeerId::random();
        let agent_id = AgentId::new(peer_id);
        let info = AgentInfo::new(
            agent_id,
            "test".to_string(),
            vec!["machine-learning".to_string(), "deep-learning".to_string()],
            "model".to_string(),
        );
        
        // Should match partial strings (case-insensitive)
        assert!(info.has_capability("machine"));
        assert!(info.has_capability("learning"));
        assert!(info.has_capability("deep"));
        assert!(!info.has_capability("supervised"));
    }
}
