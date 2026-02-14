//! Exit Policy
//!
//! Defines rules for allowing or denying traffic from the exit node.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

/// Action to take for a connection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyAction {
    /// Allow the connection
    Allow,
    /// Deny the connection
    Deny,
}

/// A rule in the exit policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Action to take
    pub action: PolicyAction,
    /// Target address pattern (simplified for now: wildcard or specific port)
    pub port: Option<u16>,
}

/// Exit Policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitPolicy {
    /// List of rules to apply in order
    pub rules: Vec<PolicyRule>,
}

impl Default for ExitPolicy {
    fn default() -> Self {
        Self {
            rules: vec![
                // Allow HTTP/HTTPS
                PolicyRule { action: PolicyAction::Allow, port: Some(80) },
                PolicyRule { action: PolicyAction::Allow, port: Some(443) },
                // Deny everything else by default
                PolicyRule { action: PolicyAction::Deny, port: None },
            ],
        }
    }
}

impl ExitPolicy {
    /// Create a new permissive policy (allow all)
    pub fn permissive() -> Self {
        Self {
            rules: vec![
                PolicyRule { action: PolicyAction::Allow, port: None },
            ],
        }
    }

    /// Check if a target address is allowed
    pub fn check(&self, _addr: &str, port: u16) -> PolicyAction {
        for rule in &self.rules {
            if let Some(rule_port) = rule.port {
                if rule_port == port {
                    return rule.action;
                }
            } else {
                // Wildcard applies to everything
                return rule.action;
            }
        }
        // Default deny if no rules match
        PolicyAction::Deny
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = ExitPolicy::default();
        assert_eq!(policy.check("google.com", 80), PolicyAction::Allow);
        assert_eq!(policy.check("google.com", 443), PolicyAction::Allow);
        assert_eq!(policy.check("google.com", 22), PolicyAction::Deny);
    }
}
