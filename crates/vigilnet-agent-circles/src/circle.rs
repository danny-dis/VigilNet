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

    // ============================================
    // Unit Tests for Core Functionality
    // ============================================

    #[test]
    fn test_circle_creation() {
        let creator_id = Uuid::new_v4();
        let circle = Circle::new(
            "Test Circle".to_string(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            10,
        );

        assert_eq!(circle.name, "Test Circle");
        assert_eq!(circle.circle_type, CircleType::Private);
        assert_eq!(circle.members.len(), 1);
        assert!(circle.members[0].is_admin);
        assert_eq!(circle.max_members, 10);
        assert_eq!(circle.current_epoch, 0);
    }

    #[test]
    fn test_circle_public_type() {
        let creator_id = Uuid::new_v4();
        let circle = Circle::new(
            "Public Circle".to_string(),
            CircleType::Public,
            creator_id,
            [0u8; 32],
            100,
        );

        assert_eq!(circle.circle_type, CircleType::Public);
        assert!(circle.circle_type.allows_anyone_join());
        assert!(!circle.circle_type.requires_audit_log());
    }

    #[test]
    fn test_circle_audit_type() {
        let creator_id = Uuid::new_v4();
        let circle = Circle::new(
            "Audit Circle".to_string(),
            CircleType::Audit,
            creator_id,
            [0u8; 32],
            50,
        );

        assert_eq!(circle.circle_type, CircleType::Audit);
        assert!(!circle.circle_type.allows_anyone_join());
        assert!(circle.circle_type.requires_audit_log());
        assert!(circle.audit_log.is_some());
        assert!(circle.members[0].is_auditor);
    }

    #[test]
    fn test_add_member() {
        let creator_id = Uuid::new_v4();
        let mut circle = Circle::new(
            "Test".to_string(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            10,
        );

        let member_id = Uuid::new_v4();
        circle
            .add_member(member_id, [1u8; 32], None)
            .expect("member should be added to circle");

        assert_eq!(circle.members.len(), 2);
        assert!(circle.is_member(member_id));
        assert_eq!(circle.current_epoch, 1);
    }

    #[test]
    fn test_add_duplicate_member() {
        let creator_id = Uuid::new_v4();
        let mut circle = Circle::new(
            "Test".to_string(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            10,
        );

        let member_id = Uuid::new_v4();
        circle
            .add_member(member_id, [1u8; 32], None)
            .expect("member should be added to circle");

        let result = circle.add_member(member_id, [1u8; 32], None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CircleError::AlreadyMember));
    }

    #[test]
    fn test_add_member_circle_full() {
        let creator_id = Uuid::new_v4();
        let mut circle = Circle::new(
            "Small Circle".to_string(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            2,
        );

        let member_id = Uuid::new_v4();
        circle
            .add_member(member_id, [1u8; 32], None)
            .expect("member should be added to circle");

        // Circle is now full
        let member_id2 = Uuid::new_v4();
        let result = circle.add_member(member_id2, [2u8; 32], None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CircleError::CircleFull));
    }

    #[test]
    fn test_remove_member() {
        let creator_id = Uuid::new_v4();
        let mut circle = Circle::new(
            "Test".to_string(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            10,
        );

        let member_id = Uuid::new_v4();
        circle
            .add_member(member_id, [1u8; 32], None)
            .expect("member should be added to circle");
        assert_eq!(circle.members.len(), 2);

        circle
            .remove_member(member_id, creator_id)
            .expect("member should be removed from circle");
        assert_eq!(circle.members.len(), 1);
        assert!(!circle.is_member(member_id));
    }

    #[test]
    fn test_remove_member_not_authorized() {
        let creator_id = Uuid::new_v4();
        let mut circle = Circle::new(
            "Test".to_string(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            10,
        );

        let member_id = Uuid::new_v4();
        circle
            .add_member(member_id, [1u8; 32], None)
            .expect("member should be added to circle");

        let non_admin_id = Uuid::new_v4();
        circle
            .add_member(non_admin_id, [2u8; 32], None)
            .expect("non-admin member should be added to circle");

        let result = circle.remove_member(member_id, non_admin_id);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CircleError::NotAuthorized(_)));
    }

    #[test]
    fn test_remove_last_admin() {
        let creator_id = Uuid::new_v4();
        let mut circle = Circle::new(
            "Test".to_string(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            10,
        );

        // Try to remove the only admin
        let result = circle.remove_member(creator_id, creator_id);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CircleError::NotAuthorized(_)));
    }

    #[test]
    fn test_remove_nonexistent_member() {
        let creator_id = Uuid::new_v4();
        let mut circle = Circle::new(
            "Test".to_string(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            10,
        );

        let nonexistent_id = Uuid::new_v4();
        let result = circle.remove_member(nonexistent_id, creator_id);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CircleError::MemberNotFound(_)));
    }

    #[test]
    fn test_get_member() {
        let creator_id = Uuid::new_v4();
        let mut circle = Circle::new(
            "Test".to_string(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            10,
        );

        let member_id = Uuid::new_v4();
        circle
            .add_member(member_id, [1u8; 32], None)
            .expect("member should be added to circle");

        let member = circle.get_member(member_id);
        assert!(member.is_some());
        assert_eq!(
            member.expect("member should exist").member_id,
            member_id
        );

        let nonexistent = circle.get_member(Uuid::new_v4());
        assert!(nonexistent.is_none());
    }

    #[test]
    fn test_is_member() {
        let creator_id = Uuid::new_v4();
        let mut circle = Circle::new(
            "Test".to_string(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            10,
        );

        assert!(circle.is_member(creator_id));

        let member_id = Uuid::new_v4();
        assert!(!circle.is_member(member_id));

        circle
            .add_member(member_id, [1u8; 32], None)
            .expect("member should be added to circle");
        assert!(circle.is_member(member_id));
    }

    #[test]
    fn test_admin_members() {
        let creator_id = Uuid::new_v4();
        let mut circle = Circle::new(
            "Test".to_string(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            10,
        );

        let admins: Vec<_> = circle.admin_members().collect();
        assert_eq!(admins.len(), 1);

        let member_id = Uuid::new_v4();
        circle
            .add_member(member_id, [1u8; 32], None)
            .expect("member should be added to circle");

        let admins: Vec<_> = circle.admin_members().collect();
        assert_eq!(admins.len(), 1); // New member is not admin
    }

    #[test]
    fn test_auditor_members() {
        let creator_id = Uuid::new_v4();
        let circle = Circle::new(
            "Audit Test".to_string(),
            CircleType::Audit,
            creator_id,
            [0u8; 32],
            10,
        );

        let auditors: Vec<_> = circle.auditor_members().collect();
        assert_eq!(auditors.len(), 1); // Creator is auditor

        // Private circle has no auditors
        let private_circle = Circle::new(
            "Private Test".to_string(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            10,
        );
        let auditors: Vec<_> = private_circle.auditor_members().collect();
        assert_eq!(auditors.len(), 0);
    }

    #[test]
    fn test_rotate_key() {
        let creator_id = Uuid::new_v4();
        let mut circle = Circle::new(
            "Test".to_string(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            10,
        );

        let old_epoch = circle.current_epoch;
        let old_key = circle.circle_key;

        circle.rotate_key();

        assert_eq!(circle.current_epoch, old_epoch + 1);
        assert_ne!(circle.circle_key, old_key);
    }

    #[test]
    fn test_set_invite_code() {
        let creator_id = Uuid::new_v4();
        let mut circle = Circle::new(
            "Test".to_string(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            10,
        );

        assert!(circle.invite_code.is_none());

        circle.set_invite_code("secret-code-123".to_string());
        assert_eq!(circle.invite_code, Some("secret-code-123".to_string()));
    }

    #[test]
    fn test_add_admin_escrow_key() {
        let creator_id = Uuid::new_v4();
        let mut circle = Circle::new(
            "Audit Test".to_string(),
            CircleType::Audit,
            creator_id,
            [0u8; 32],
            10,
        );

        let escrow_key = [1u8; 32];
        circle
            .add_admin_escrow_key(escrow_key)
            .expect("admin escrow key should be added");
        assert_eq!(circle.admin_escrow_keys.len(), 1);

        // Try on non-audit circle
        let mut private_circle = Circle::new(
            "Private".to_string(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            10,
        );
        let result = private_circle.add_admin_escrow_key(escrow_key);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CircleError::InvalidCircleType));
    }

    #[test]
    fn test_get_audit_log() {
        let creator_id = Uuid::new_v4();
        let circle = Circle::new(
            "Audit Test".to_string(),
            CircleType::Audit,
            creator_id,
            [0u8; 32],
            10,
        );

        let log = circle.get_audit_log();
        assert!(log.is_some());
        assert_eq!(
            log.expect("audit log should exist").len(),
            1
        ); // CircleCreated event

        // Private circle has no audit log
        let private_circle = Circle::new(
            "Private".to_string(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            10,
        );
        assert!(private_circle.get_audit_log().is_none());
    }

    #[test]
    fn test_export_for_audit() {
        let creator_id = Uuid::new_v4();
        let circle = Circle::new(
            "Audit Test".to_string(),
            CircleType::Audit,
            creator_id,
            [0u8; 32],
            10,
        );

        let export = circle.export_for_audit(creator_id);
        assert!(export.is_ok());

        let export = export.expect("export should succeed");
        assert_eq!(export.circle_name, "Audit Test");
        assert_eq!(export.members.len(), 1);
        assert_eq!(export.current_epoch, 0);

        // Try on non-audit circle
        let private_circle = Circle::new(
            "Private".to_string(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            10,
        );
        let result = private_circle.export_for_audit(creator_id);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CircleError::InvalidCircleType));

        // Try with non-auditor
        let mut circle = Circle::new(
            "Audit Test 2".to_string(),
            CircleType::Audit,
            creator_id,
            [0u8; 32],
            10,
        );
        let member_id = Uuid::new_v4();
        circle
            .add_member(member_id, [1u8; 32], None)
            .expect("member should be added to circle");

        let result = circle.export_for_audit(member_id);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CircleError::NotAuthorized(_)));
    }

    // ============================================
    // AuditEntry and AuditEventType Tests
    // ============================================

    #[test]
    fn test_audit_entry_creation() {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            event_type: AuditEventType::CircleCreated {
                creator_id: Uuid::new_v4(),
                circle_name: "Test".to_string(),
            },
            actor_id: Uuid::new_v4(),
            details: "Test details".to_string(),
        };

        assert!(!entry.details.is_empty());
    }

    #[test]
    fn test_audit_event_types() {
        let events = vec![
            AuditEventType::CircleCreated {
                creator_id: Uuid::new_v4(),
                circle_name: "Test".to_string(),
            },
            AuditEventType::MemberAdded { member_id: Uuid::new_v4() },
            AuditEventType::MemberRemoved { member_id: Uuid::new_v4() },
            AuditEventType::MemberKeyRotated { member_id: Uuid::new_v4() },
            AuditEventType::AdminKeyEscrowAdded,
            AuditEventType::InviteGenerated { invite_id: Uuid::new_v4() },
            AuditEventType::InviteUsed {
                invite_id: Uuid::new_v4(),
                member_id: Uuid::new_v4(),
            },
            AuditEventType::CircleTypeChanged {
                from: CircleType::Private,
                to: CircleType::Public,
            },
            AuditEventType::ComplianceLog {
                message: "Test".to_string(),
            },
        ];

        assert_eq!(events.len(), 9);
    }

    // ============================================
    // AuditExport Tests
    // ============================================

    #[test]
    fn test_audit_export() {
        let export = AuditExport {
            circle_id: Uuid::new_v4(),
            circle_name: "Test".to_string(),
            members: vec![],
            audit_log: vec![],
            current_epoch: 0,
            auditor_public_key: [0u8; 32],
        };

        assert!(!export.circle_name.is_empty());
    }

    // ============================================
    // CircleManager Tests
    // ============================================

    #[tokio::test]
    async fn test_circle_manager_creation() {
        let manager = CircleManager::new();
        assert!(manager.list_circles().await.is_empty());
    }

    #[tokio::test]
    async fn test_circle_manager_create_circle() {
        let manager = CircleManager::new();
        let creator_id = Uuid::new_v4();

        let circle = manager
            .create_circle(
                "Test Circle".to_string(),
                CircleType::Private,
                creator_id,
                [0u8; 32],
                10,
            )
            .await
            .expect("circle should be created");

        let circles = manager.list_circles().await;
        assert_eq!(circles.len(), 1);

        let circle_guard = circle.read().await;
        assert_eq!(circle_guard.name, "Test Circle");
    }

    #[tokio::test]
    async fn test_circle_manager_get_circle() {
        let manager = CircleManager::new();
        let creator_id = Uuid::new_v4();

        let circle = manager
            .create_circle(
                "Test".to_string(),
                CircleType::Private,
                creator_id,
                [0u8; 32],
                10,
            )
            .await
            .expect("circle should be created");

        let circle_id = circle.read().await.circle_id;

        let retrieved = manager.get_circle(circle_id).await;
        assert!(retrieved.is_ok());

        let nonexistent_id = Uuid::new_v4();
        let result = manager.get_circle(nonexistent_id).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CircleError::CircleNotFound(_)));
    }

    #[tokio::test]
    async fn test_circle_manager_list_circles() {
        let manager = CircleManager::new();
        let creator_id = Uuid::new_v4();

        for i in 0..5 {
            manager
                .create_circle(
                    format!("Circle {}", i),
                    CircleType::Private,
                    creator_id,
                    [0u8; 32],
                    10,
                )
                .await
                .expect("circle should be created");
        }

        let circles = manager.list_circles().await;
        assert_eq!(circles.len(), 5);
    }

    #[tokio::test]
    async fn test_circle_manager_delete_circle() {
        let manager = CircleManager::new();
        let creator_id = Uuid::new_v4();

        let circle = manager
            .create_circle(
                "Test".to_string(),
                CircleType::Private,
                creator_id,
                [0u8; 32],
                10,
            )
            .await
            .expect("circle should be created");

        let circle_id = circle.read().await.circle_id;
        assert_eq!(manager.list_circles().await.len(), 1);

        // Delete with wrong user
        let other_id = Uuid::new_v4();
        let result = manager.delete_circle(circle_id, other_id).await;
        assert!(result.is_err());

        // Delete with creator
        manager
            .delete_circle(circle_id, creator_id)
            .await
            .expect("circle should be deleted by creator");
        assert!(manager.list_circles().await.is_empty());
    }

    #[tokio::test]
    async fn test_circle_manager_default() {
        let manager: CircleManager = Default::default();
        assert!(manager.list_circles().await.is_empty());
    }

    // ============================================
    // Error Handling Tests
    // ============================================

    #[test]
    fn test_circle_error_variants() {
        let errors = vec![
            CircleError::CircleNotFound("test".to_string()),
            CircleError::MemberNotFound("test".to_string()),
            CircleError::AlreadyMember,
            CircleError::NotAuthorized("test".to_string()),
            CircleError::InvalidCircleType,
            CircleError::CircleFull,
            CircleError::AuditError("test".to_string()),
            CircleError::EncryptionError("test".to_string()),
        ];

        for err in errors {
            let msg = err.to_string();
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn test_circle_error_display() {
        let err = CircleError::NotAuthorized("test error".to_string());
        assert!(err.to_string().contains("Not authorized"));
        assert!(err.to_string().contains("test error"));
    }

    // ============================================
    // Edge Case Tests
    // ============================================

    #[test]
    fn test_circle_with_empty_name() {
        let creator_id = Uuid::new_v4();
        let circle = Circle::new(
            "".to_string(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            10,
        );
        assert!(circle.name.is_empty());
    }

    #[test]
    fn test_circle_with_long_name() {
        let creator_id = Uuid::new_v4();
        let long_name = "a".repeat(1000);
        let circle = Circle::new(
            long_name.clone(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            10,
        );
        assert_eq!(circle.name.len(), 1000);
    }

    #[test]
    fn test_circle_max_members_edge_cases() {
        let creator_id = Uuid::new_v4();

        // Max members = 1 (just creator)
        let circle = Circle::new(
            "Tiny".to_string(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            1,
        );
        assert_eq!(circle.members.len(), 1);

        // Max members = 0 (edge case)
        let circle = Circle::new(
            "Zero".to_string(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            0,
        );
        assert_eq!(circle.members.len(), 1); // Creator still added
    }

    #[test]
    fn test_circle_many_members() {
        let creator_id = Uuid::new_v4();
        let mut circle = Circle::new(
            "Large".to_string(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            1000,
        );

        for i in 0..100 {
            let member_id = Uuid::new_v4();
            circle
                .add_member(member_id, [i as u8; 32], None)
                .expect("member should be added to circle");
        }

        assert_eq!(circle.members.len(), 101);
    }

    #[test]
    fn test_circle_member_with_signing_key() {
        let creator_id = Uuid::new_v4();
        let mut circle = Circle::new(
            "Test".to_string(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            10,
        );

        let member_id = Uuid::new_v4();
        let signing_key = [5u8; 32];
        circle
            .add_member(member_id, [1u8; 32], Some(signing_key))
            .expect("member should be added with signing key");

        let member = circle
            .get_member(member_id)
            .expect("member should exist");
        assert_eq!(member.signing_key, Some(signing_key));
    }

    #[test]
    fn test_audit_log_growth() {
        let creator_id = Uuid::new_v4();
        let mut circle = Circle::new(
            "Audit".to_string(),
            CircleType::Audit,
            creator_id,
            [0u8; 32],
            100,
        );

        let initial_len = circle
            .get_audit_log()
            .expect("audit log should exist")
            .len();

        // Add members to generate audit log entries
        for _ in 0..5 {
            let member_id = Uuid::new_v4();
            circle
                .add_member(member_id, [1u8; 32], None)
                .expect("member should be added to circle");
        }

        let final_len = circle
            .get_audit_log()
            .expect("audit log should exist")
            .len();
        assert_eq!(final_len, initial_len + 5);
    }

    #[test]
    fn test_circle_key_changes_on_member_add() {
        let creator_id = Uuid::new_v4();
        let mut circle = Circle::new(
            "Test".to_string(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            10,
        );

        let initial_key = circle.circle_key;

        circle
            .add_member(Uuid::new_v4(), [1u8; 32], None)
            .expect("member should be added to circle");
        assert_ne!(circle.circle_key, initial_key);

        let second_key = circle.circle_key;
        circle
            .add_member(Uuid::new_v4(), [2u8; 32], None)
            .expect("member should be added to circle");
        assert_ne!(circle.circle_key, second_key);
    }

    #[tokio::test]
    async fn test_circle_manager_concurrent_access() {
        use std::sync::Arc;

        let manager = Arc::new(CircleManager::new());
        let mut handles = vec![];

        for i in 0..10 {
            let mgr = Arc::clone(&manager);
            let handle = tokio::spawn(async move {
                mgr.create_circle(
                    format!("Circle {}", i),
                    CircleType::Private,
                    Uuid::new_v4(),
                    [0u8; 32],
                    10,
                )
                .await
            });
            handles.push(handle);
        }

        for handle in handles {
            handle
                .await
                .expect("task should complete")
                .expect("circle should be created");
        }

        assert_eq!(manager.list_circles().await.len(), 10);
    }

    #[test]
    fn test_circle_serialization() {
        let creator_id = Uuid::new_v4();
        let circle = Circle::new(
            "Test".to_string(),
            CircleType::Audit,
            creator_id,
            [0u8; 32],
            10,
        );

        let serialized = serde_json::to_string(&circle).expect("circle should serialize");
        let deserialized: Circle =
            serde_json::from_str(&serialized).expect("circle should deserialize");

        assert_eq!(circle.circle_id, deserialized.circle_id);
        assert_eq!(circle.name, deserialized.name);
        assert_eq!(circle.members.len(), deserialized.members.len());
    }

    #[test]
    fn test_circle_clone() {
        let creator_id = Uuid::new_v4();
        let circle = Circle::new(
            "Test".to_string(),
            CircleType::Private,
            creator_id,
            [0u8; 32],
            10,
        );

        let cloned = circle.clone();
        assert_eq!(circle.circle_id, cloned.circle_id);
        assert_eq!(circle.name, cloned.name);
    }

    #[test]
    fn test_circle_type_equality() {
        assert_eq!(CircleType::Public, CircleType::Public);
        assert_eq!(CircleType::Private, CircleType::Private);
        assert_eq!(CircleType::Audit, CircleType::Audit);
        assert_ne!(CircleType::Public, CircleType::Private);
        assert_ne!(CircleType::Private, CircleType::Audit);
    }

    #[test]
    fn test_circle_type_debug() {
        let debug_str = format!("{:?}", CircleType::Audit);
        assert!(debug_str.contains("Audit"));
    }

    #[test]
    fn test_circle_member_clone() {
        let member = CircleMember {
            member_id: Uuid::new_v4(),
            identity_key: [1u8; 32],
            signing_key: Some([2u8; 32]),
            joined_at: Utc::now(),
            is_admin: true,
            is_auditor: false,
            encrypted_key_share: None,
        };

        let cloned = member.clone();
        assert_eq!(member.member_id, cloned.member_id);
        assert_eq!(member.identity_key, cloned.identity_key);
    }

    #[test]
    fn test_audit_entry_clone() {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            event_type: AuditEventType::AdminKeyEscrowAdded,
            actor_id: Uuid::new_v4(),
            details: "test".to_string(),
        };

        let cloned = entry.clone();
        assert_eq!(entry.details, cloned.details);
    }
}
