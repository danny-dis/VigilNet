use crate::crypto::{derive_group_key, CircleCipher, KeyEpoch};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum CircleError {
    #[error("Circle not found: {0}")]
    CircleNotFound(String),
    #[error("Member not found: {0}")]
    MemberNotFound(String),
    #[error("Already a member")]
    AlreadyMember,
    #[error("Not authorized: {0}")]
    NotAuthorized(String),
    #[error("Invalid circle type for operation")]
    InvalidCircleType,
    #[error("Circle full: maximum members reached")]
    CircleFull,
    #[error("Audit error: {0}")]
    AuditError(String),
    #[error("Encryption error: {0}")]
    EncryptionError(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CircleType {
    Public,
    Private,
    Audit,
}

impl CircleType {
    pub fn requires_audit_log(&self) -> bool {
        matches!(self, CircleType::Audit)
    }

    pub fn allows_anyone_join(&self) -> bool {
        matches!(self, CircleType::Public)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircleMember {
    pub member_id: Uuid,
    pub identity_key: [u8; 32],
    pub signing_key: Option<[u8; 32]>,
    pub joined_at: DateTime<Utc>,
    pub is_admin: bool,
    pub is_auditor: bool,
    pub encrypted_key_share: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Circle {
    pub circle_id: Uuid,
    pub name: String,
    pub circle_type: CircleType,
    pub members: Vec<CircleMember>,
    pub circle_key: [u8; 32],
    pub created_at: DateTime<Utc>,
    pub created_by: Uuid,
    pub current_epoch: u64,
    pub max_members: usize,
    pub invite_code: Option<String>,
    pub audit_log: Option<Vec<AuditEntry>>,
    pub admin_escrow_keys: Vec<[u8; 32]>,
}

impl Circle {
    pub fn new(
        name: String,
        circle_type: CircleType,
        creator_id: Uuid,
        creator_identity_key: [u8; 32],
        max_members: usize,
    ) -> Self {
        let mut rng = rand::thread_rng();
        let mut circle_key = [0u8; 32];
        rng.fill_bytes(&mut circle_key);

        let creator_member = CircleMember {
            member_id: creator_id,
            identity_key: creator_identity_key,
            signing_key: None,
            joined_at: Utc::now(),
            is_admin: true,
            is_auditor: circle_type == CircleType::Audit,
            encrypted_key_share: None,
        };

        let mut members = vec![creator_member];
        let audit_log = if circle_type.requires_audit_log() {
            Some(vec![AuditEntry {
                timestamp: Utc::now(),
                event_type: AuditEventType::CircleCreated {
                    creator_id,
                    circle_name: name.clone(),
                },
                actor_id: creator_id,
                details: format!("Circle '{}' created with Audit type", name),
            }])
        } else {
            None
        };

        Self {
            circle_id: Uuid::new_v4(),
            name,
            circle_type,
            members,
            circle_key,
            created_at: Utc::now(),
            created_by: creator_id,
            current_epoch: 0,
            max_members,
            invite_code: None,
            audit_log,
            admin_escrow_keys: Vec::new(),
        }
    }

    pub fn add_member(
        &mut self,
        member_id: Uuid,
        identity_key: [u8; 32],
        signing_key: Option<[u8; 32]>,
    ) -> Result<(), CircleError> {
        if self.members.len() >= self.max_members {
            return Err(CircleError::CircleFull);
        }

        if self.members.iter().any(|m| m.member_id == member_id) {
            return Err(CircleError::AlreadyMember);
        }

        let member = CircleMember {
            member_id,
            identity_key,
            signing_key,
            joined_at: Utc::now(),
            is_admin: false,
            is_auditor: false,
            encrypted_key_share: None,
        };

        self.members.push(member);
        self.current_epoch += 1;
        self.rederive_circle_key();

        if let Some(ref mut log) = self.audit_log {
            log.push(AuditEntry {
                timestamp: Utc::now(),
                event_type: AuditEventType::MemberAdded { member_id },
                actor_id: self.created_by,
                details: format!("Member {} added to circle", member_id),
            });
        }

        Ok(())
    }

    pub fn remove_member(&mut self, member_id: Uuid, remover_id: Uuid) -> Result<(), CircleError> {
        let remover = self
            .members
            .iter()
            .find(|m| m.member_id == remover_id)
            .ok_or(CircleError::MemberNotFound(remover_id.to_string()))?;

        if !remover.is_admin {
            return Err(CircleError::NotAuthorized(
                "Only admins can remove members".into(),
            ));
        }

        let pos = self
            .members
            .iter()
            .position(|m| m.member_id == member_id)
            .ok_or(CircleError::MemberNotFound(member_id.to_string()))?;

        if self.members[pos].is_admin && self.admin_members().count() == 1 {
            return Err(CircleError::NotAuthorized(
                "Cannot remove the last admin".into(),
            ));
        }

        self.members.remove(pos);
        self.current_epoch += 1;
        self.rederive_circle_key();

        if let Some(ref mut log) = self.audit_log {
            log.push(AuditEntry {
                timestamp: Utc::now(),
                event_type: AuditEventType::MemberRemoved { member_id },
                actor_id: remover_id,
                details: format!("Member {} removed from circle", member_id),
            });
        }

        Ok(())
    }

    pub fn get_member(&self, member_id: Uuid) -> Option<&CircleMember> {
        self.members.iter().find(|m| m.member_id == member_id)
    }

    pub fn is_member(&self, member_id: Uuid) -> bool {
        self.members.iter().any(|m| m.member_id == member_id)
    }

    pub fn admin_members(&self) -> impl Iterator<Item = &CircleMember> {
        self.members.iter().filter(|m| m.is_admin)
    }

    pub fn auditor_members(&self) -> impl Iterator<Item = &CircleMember> {
        self.members.iter().filter(|m| m.is_auditor)
    }

    pub fn rotate_key(&mut self) {
        self.current_epoch += 1;
        self.rederive_circle_key();
    }

    fn rederive_circle_key(&mut self) {
        let member_keys: Vec<&[u8]> = self.members.iter().map(|m| m.identity_key.as_slice()).collect();
        self.circle_key = derive_group_key(&member_keys);
    }

    pub fn set_invite_code(&mut self, code: String) {
        self.invite_code = Some(code);
    }

    pub fn add_admin_escrow_key(&mut self, key: [u8; 32]) -> Result<(), CircleError> {
        if !matches!(self.circle_type, CircleType::Audit) {
            return Err(CircleError::InvalidCircleType);
        }
        self.admin_escrow_keys.push(key);

        if let Some(ref mut log) = self.audit_log {
            log.push(AuditEntry {
                timestamp: Utc::now(),
                event_type: AuditEventType::AdminKeyEscrowAdded,
                actor_id: self.created_by,
                details: "Admin key escrow added".to_string(),
            });
        }

        Ok(())
    }

    pub fn get_audit_log(&self) -> Option<&[AuditEntry]> {
        self.audit_log.as_deref()
    }

    pub fn export_for_audit(&self, auditor_id: Uuid) -> Result<AuditExport, CircleError> {
        if !matches!(self.circle_type, CircleType::Audit) {
            return Err(CircleError::InvalidCircleType);
        }

        let auditor = self
            .members
            .iter()
            .find(|m| m.member_id == auditor_id && m.is_auditor)
            .ok_or(CircleError::NotAuthorized("Not an auditor".into()))?;

        Ok(AuditExport {
            circle_id: self.circle_id,
            circle_name: self.name.clone(),
            members: self.members.clone(),
            audit_log: self.audit_log.clone().unwrap_or_default(),
            current_epoch: self.current_epoch,
            auditor_public_key: auditor.identity_key,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub actor_id: Uuid,
    pub details: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AuditEventType {
    CircleCreated { creator_id: Uuid, circle_name: String },
    MemberAdded { member_id: Uuid },
    MemberRemoved { member_id: Uuid },
    MemberKeyRotated { member_id: Uuid },
    AdminKeyEscrowAdded,
    InviteGenerated { invite_id: Uuid },
    InviteUsed { invite_id: Uuid, member_id: Uuid },
    CircleTypeChanged { from: CircleType, to: CircleType },
    ComplianceLog { message: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditExport {
    pub circle_id: Uuid,
    pub circle_name: String,
    pub members: Vec<CircleMember>,
    pub audit_log: Vec<AuditEntry>,
    pub current_epoch: u64,
    pub auditor_public_key: [u8; 32],
}

pub struct CircleManager {
    circles: HashMap<Uuid, Arc<RwLock<Circle>>>,
}

impl CircleManager {
    pub fn new() -> Self {
        Self {
            circles: HashMap::new(),
        }
    }

    pub async fn create_circle(
        &self,
        name: String,
        circle_type: CircleType,
        creator_id: Uuid,
        creator_identity_key: [u8; 32],
        max_members: usize,
    ) -> Result<Arc<RwLock<Circle>>, CircleError> {
        let circle = Circle::new(
            name,
            circle_type,
            creator_id,
            creator_identity_key,
            max_members,
        );
        let circle_id = circle.circle_id;
        let circle = Arc::new(RwLock::new(circle));
        self.circles.insert(circle_id, circle.clone());
        Ok(circle)
    }

    pub async fn get_circle(&self, circle_id: Uuid) -> Result<Arc<RwLock<Circle>>, CircleError> {
        self.circles
            .get(&circle_id)
            .cloned()
            .ok_or(CircleError::CircleNotFound(circle_id.to_string()))
    }

    pub async fn list_circles(&self) -> Vec<Uuid> {
        self.circles.keys().copied().collect()
    }

    pub async fn delete_circle(&self, circle_id: Uuid, requester_id: Uuid) -> Result<(), CircleError> {
        let circle = self.get_circle(circle_id).await?;
        let circle = circle.read().await;

        if circle.created_by != requester_id {
            return Err(CircleError::NotAuthorized(
                "Only circle creator can delete".into(),
            ));
        }

        self.circles.remove(&circle_id);
        Ok(())
    }
}

impl Default for CircleManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circle_creation() {
        let circle = Circle::new(
            "Test Circle".to_string(),
            CircleType::Private,
            Uuid::new_v4(),
            [0u8; 32],
            10,
        );

        assert_eq!(circle.name, "Test Circle");
        assert_eq!(circle.circle_type, CircleType::Private);
        assert_eq!(circle.members.len(), 1);
        assert!(circle.members[0].is_admin);
    }

    #[test]
    fn test_add_member() {
        let mut circle = Circle::new(
            "Test".to_string(),
            CircleType::Private,
            Uuid::new_v4(),
            [0u8; 32],
            10,
        );

        let member_id = Uuid::new_v4();
        circle.add_member(member_id, [1u8; 32], None).unwrap();

        assert_eq!(circle.members.len(), 2);
        assert!(circle.is_member(member_id));
    }

    #[test]
    fn test_audit_circle() {
        let circle = Circle::new(
            "HIPAA Circle".to_string(),
            CircleType::Audit,
            Uuid::new_v4(),
            [0u8; 32],
            10,
        );

        assert!(circle.audit_log.is_some());
        assert!(circle.requires_audit_log());
    }
}
