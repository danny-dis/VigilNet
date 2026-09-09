pub mod circle;
pub mod crypto;
pub mod invite;

pub use circle::{
    AuditEntry, AuditEventType, AuditExport, Circle, CircleError, CircleManager, CircleMember,
    CircleType,
};
pub use crypto::{
    CircleCipher, CircleCryptoError, KeyEpoch, derive_group_key, derive_key_pair_from_seed,
    compute_shared_secret, hash_to_scalar,
};
pub use invite::{
    FeldmanVss, Invite, InviteError, InviteManager, InviteShare, InviteToken,
    ShamirSecretSharing,
};

use anyhow::Result;
use chrono;
use circle::{CircleManager, CircleType};
use crypto::CircleCipher;
use invite::InviteManager;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct CirclesService {
    circle_manager: Arc<RwLock<CircleManager>>,
    invite_manager: Arc<RwLock<InviteManager>>,
    member_ciphers: HashMap<(Uuid, Uuid), Arc<RwLock<CircleCipher>>>,
}

impl CirclesService {
    pub fn new() -> Self {
        Self {
            circle_manager: Arc::new(RwLock::new(CircleManager::new())),
            invite_manager: Arc::new(RwLock::new(InviteManager::new())),
            member_ciphers: HashMap::new(),
        }
    }

    pub async fn create_circle(
        &self,
        name: String,
        circle_type: CircleType,
        creator_id: Uuid,
        creator_identity_key: [u8; 32],
        max_members: usize,
    ) -> Result<Uuid, CircleError> {
        let circle = self
            .circle_manager
            .create_circle(
                name,
                circle_type,
                creator_id,
                creator_identity_key,
                max_members,
            )
            .await?;

        let circle_id = circle.read().await.circle_id;
        Ok(circle_id)
    }

    pub async fn create_invite(
        &self,
        circle_id: Uuid,
        threshold: u8,
        num_shares: u8,
        issuer_id: Uuid,
        max_uses: Option<u32>,
        validity_hours: i64,
    ) -> Result<Invite, InviteError> {
        let mut manager = self.invite_manager.write().await;
        manager.create_invite(
            circle_id,
            threshold,
            num_shares,
            issuer_id,
            max_uses,
            chrono::Duration::hours(validity_hours),
        )
    }

    pub async fn get_circle(&self, circle_id: Uuid) -> Result<circle::Circle, CircleError> {
        let circle = self.circle_manager.get_circle(circle_id).await?;
        Ok(circle.read().await.clone())
    }

    pub async fn list_circles(&self) -> Vec<Uuid> {
        self.circle_manager.list_circles().await
    }

    pub async fn add_member(
        &self,
        circle_id: Uuid,
        member_id: Uuid,
        identity_key: [u8; 32],
        signing_key: Option<[u8; 32]>,
    ) -> Result<(), CircleError> {
        let circle = self.circle_manager.get_circle(circle_id).await?;
        let mut circle = circle.write().await;
        circle.add_member(member_id, identity_key, signing_key)?;
        Ok(())
    }

    pub async fn remove_member(
        &self,
        circle_id: Uuid,
        member_id: Uuid,
        remover_id: Uuid,
    ) -> Result<(), CircleError> {
        let circle = self.circle_manager.get_circle(circle_id).await?;
        let mut circle = circle.write().await;
        circle.remove_member(member_id, remover_id)
    }

    pub async fn encrypt_for_circle(
        &self,
        circle_id: Uuid,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CircleCryptoError> {
        let circle = self.circle_manager.get_circle(circle_id).await.map_err(|e| {
            CircleCryptoError::EncryptionFailed(e.to_string())
        })?;
        let circle = circle.read().await;

        let cipher = CircleCipher::new(&circle.circle_key, circle.current_epoch);
        cipher.encrypt(plaintext)
    }

    pub async fn decrypt_for_circle(
        &self,
        circle_id: Uuid,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CircleCryptoError> {
        let circle = self.circle_manager.get_circle(circle_id).await.map_err(|e| {
            CircleCryptoError::DecryptionFailed(e.to_string())
        })?;
        let circle = circle.read().await;

        let cipher = CircleCipher::new(&circle.circle_key, circle.current_epoch);
        cipher.decrypt(ciphertext)
    }

    pub async fn rotate_circle_key(&self, circle_id: Uuid) -> Result<(), CircleError> {
        let circle = self.circle_manager.get_circle(circle_id).await?;
        let mut circle = circle.write().await;
        circle.rotate_key();
        Ok(())
    }

    pub async fn get_audit_log(
        &self,
        circle_id: Uuid,
    ) -> Result<Option<Vec<AuditEntry>>, CircleError> {
        let circle = self.circle_manager.get_circle(circle_id).await?;
        let circle = circle.read().await;
        Ok(circle.get_audit_log().map(|v| v.to_vec()))
    }

    pub async fn export_audit(
        &self,
        circle_id: Uuid,
        auditor_id: Uuid,
    ) -> Result<AuditExport, CircleError> {
        let circle = self.circle_manager.get_circle(circle_id).await?;
        let circle = circle.read().await;
        circle.export_for_audit(auditor_id)
    }

    pub async fn validate_invite(&self, token: &InviteToken) -> Result<Invite, InviteError> {
        let manager = self.invite_manager.read().await;
        manager.validate_token(token)
    }
}

impl Default for CirclesService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_full_circle_lifecycle() {
        let service = CirclesService::new();
        let creator_id = Uuid::new_v4();
        let creator_key = [1u8; 32];

        let circle_id = service
            .create_circle(
                "Test HIPAA Circle".to_string(),
                CircleType::Audit,
                creator_id,
                creator_key,
                10,
            )
            .await
            .expect("Failed to create circle");

        let invite = service
            .create_invite(circle_id, 2, 3, creator_id, Some(10), 24)
            .await
            .expect("Failed to create invite");

        assert!(!invite.shares.is_empty());

        let member_id = Uuid::new_v4();
        let member_key = [2u8; 32];
        service
            .add_member(circle_id, member_id, member_key, None)
            .await
            .expect("Failed to add member");

        let plaintext = b"Protected health information";
        let ciphertext = service
            .encrypt_for_circle(circle_id, plaintext)
            .await
            .expect("Failed to encrypt for circle");
        let decrypted = service
            .decrypt_for_circle(circle_id, &ciphertext)
            .await
            .expect("Failed to decrypt for circle");

        assert_eq!(plaintext.to_vec(), decrypted);

        let audit_log = service.get_audit_log(circle_id).await.expect("Failed to get audit log");
        assert!(audit_log.is_some());
    }

    #[tokio::test]
    async fn test_private_circle() {
        let service = CirclesService::new();
        let creator_id = Uuid::new_v4();
        let creator_key = [1u8; 32];

        let circle_id = service
            .create_circle(
                "Private Circle".to_string(),
                CircleType::Private,
                creator_id,
                creator_key,
                5,
            )
            .await
            .expect("Failed to create private circle");

        let member_id = Uuid::new_v4();
        service
            .add_member(circle_id, member_id, [2u8; 32], None)
            .await
            .expect("Failed to add member to private circle");

        let circle = service.get_circle(circle_id).await.expect("Failed to get circle");
        assert_eq!(circle.circle_type, CircleType::Private);
        assert_eq!(circle.members.len(), 2);
    }
}
