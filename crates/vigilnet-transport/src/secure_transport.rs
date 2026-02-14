//! Secure Transport with End-to-End Encryption
//!
//! Provides E2EE wrapper for any transport using Signal Protocol (Double Ratchet)

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use vigilnet_crypto::{
    session::{MessageType, Session, SessionMessage, SessionState},
    x3dh::{IdentityKeyPair, OneTimePreKey, PreKeyBundle, SignedPreKey},
    CryptoError, Result as CryptoResult,
};

use crate::{TransportError, TransportResult};

const DEFAULT_OTK_COUNT: usize = 100;
const SESSION_EXPIRY_SECS: u64 = 86400;
const MAX_SESSION_COUNT: usize = 1000;

pub struct SessionManager {
    local_identity: IdentityKeyPair,
    sessions: RwLock<HashMap<String, Session>>,
    pre_key_bundle: RwLock<Option<PreKeyBundle>>,
    signed_pre_key: RwLock<Option<SignedPreKey>>,
    one_time_keys: RwLock<HashMap<u32, OneTimePreKey>>,
    next_otk_id: RwLock<u32>,
    session_timestamps: RwLock<HashMap<String, Instant>>,
    stats: RwLock<SessionStats>,
}

#[derive(Default)]
struct SessionStats {
    active_sessions: usize,
    total_sessions_created: usize,
    total_messages_encrypted: u64,
    total_messages_decrypted: u64,
    session_creations_failed: u64,
}

impl SessionManager {
    pub fn new() -> Self {
        let local_identity = IdentityKeyPair::generate();
        let signed_pre_key = SignedPreKey::generate(&local_identity, 1);

        Self {
            local_identity,
            sessions: RwLock::new(HashMap::new()),
            pre_key_bundle: RwLock::new(None),
            signed_pre_key: RwLock::new(Some(signed_pre_key)),
            one_time_keys: RwLock::new(HashMap::new()),
            next_otk_id: RwLock::new(1),
            session_timestamps: RwLock::new(HashMap::new()),
            stats: RwLock::new(SessionStats::default()),
        }
    }

    pub async fn initialize(&self) -> CryptoResult<()> {
        self.generate_one_time_keys(DEFAULT_OTK_COUNT).await?;
        self.generate_prekey_bundle().await?;
        info!("Session manager initialized with {} OTKs", DEFAULT_OTK_COUNT);
        Ok(())
    }

    pub async fn generate_prekey_bundle(&self) -> CryptoResult<PreKeyBundle> {
        let signed_pre_key = self.signed_pre_key.read().await;
        let spk = signed_pre_key.as_ref().ok_or_else(|| {
            CryptoError::SessionError("No signed pre-key available".to_string())
        })?;

        let mut otks = self.one_time_keys.write().await;
        let otpk = otks.values().next().cloned();

        let bundle = PreKeyBundle {
            identity_key: self.local_identity.identity_public,
            signed_prekey: spk.clone(),
            one_time_prekey: otpk,
        };

        *self.pre_key_bundle.write().await = Some(bundle.clone());
        Ok(bundle)
    }

    pub async fn get_prekey_bundle(&self) -> CryptoResult<PreKeyBundle> {
        if let Some(bundle) = self.pre_key_bundle.read().await.as_ref() {
            return Ok(bundle.clone());
        }
        self.generate_prekey_bundle().await
    }

    pub async fn rotate_signed_prekey(&self) -> CryptoResult<()> {
        let mut next_id = self.next_otk_id.write().await;
        let new_spk = SignedPreKey::generate(&self.local_identity, *next_id);
        *self.signed_pre_key.write().await = Some(new_spk);
        *next_id += 1;
        
        self.generate_prekey_bundle().await?;
        
        info!("Rotated signed pre-key");
        Ok(())
    }

    pub async fn generate_one_time_keys(&self, count: usize) -> CryptoResult<()> {
        let mut otks = self.one_time_keys.write().await;
        let mut next_id = self.next_otk_id.write().await;

        for i in 0..count {
            let otpk = OneTimePreKey::generate(*next_id + i as u32);
            otks.insert(otpk.id, otpk);
        }

        *next_id += count as u32;
        info!("Generated {} one-time pre-keys (total: {})", count, otks.len());
        Ok(())
    }

    pub async fn get_otk_count(&self) -> usize {
        self.one_time_keys.read().await.len()
    }

    pub async fn create_session_initiator(
        &self,
        peer_identity: [u8; 32],
        bundle: &PreKeyBundle,
    ) -> CryptoResult<(String, SessionMessage)> {
        if self.sessions.read().await.len() >= MAX_SESSION_COUNT {
            return Err(CryptoError::SessionError(
                "Maximum session count reached".to_string(),
            ));
        }

        let (session, message) = Session::create_initiator(bundle, peer_identity)?;
        let session_id = session.session_id().to_string();

        self.sessions
            .write()
            .await
            .insert(session_id.clone(), session);
        
        self.session_timestamps
            .write()
            .await
            .insert(session_id.clone(), Instant::now());

        let mut stats = self.stats.write().await;
        stats.active_sessions += 1;
        stats.total_sessions_created += 1;

        debug!("Created initiator session: {}", session_id);
        Ok((session_id, message))
    }

    pub async fn process_session_message(
        &self,
        peer_identity: [u8; 32],
        message: &SessionMessage,
    ) -> CryptoResult<(String, Vec<u8>)> {
        match &message.message_type {
            MessageType::X3DHPreKey {
                identity_key,
                ephemeral_key,
                spk_id,
                otpk_id,
            } => {
                let spk = self.signed_pre_key.read().await;
                let spk = spk.as_ref().ok_or_else(|| {
                    CryptoError::SessionError("No signed pre-key available".to_string())
                })?;

                let otk = if let Some(id) = otpk_id {
                    let mut otks = self.one_time_keys.write().await;
                    if let Some(otpk) = otks.remove(id) {
                        Some(otpk)
                    } else {
                        warn!("One-time pre-key {} not found", id);
                        None
                    }
                } else {
                    None
                };

                let session = Session::create_responder(
                    &self.local_identity,
                    spk,
                    otk.as_ref(),
                    *identity_key,
                    *ephemeral_key,
                    *spk_id,
                    *otpk_id,
                )?;

                let session_id = session.session_id().to_string();
                self.sessions
                    .write()
                    .await
                    .insert(session_id.clone(), session);

                self.session_timestamps
                    .write()
                    .await
                    .insert(session_id.clone(), Instant::now());

                let mut stats = self.stats.write().await;
                stats.active_sessions += 1;
                stats.total_sessions_created += 1;

                info!("Created responder session: {}", session_id);
                Ok((session_id, vec![]))
            }
            MessageType::RatchetMessage(_) => {
                let mut sessions = self.sessions.write().await;
                if let Some(session) = sessions.get_mut(&message.session_id) {
                    let plaintext = session.decrypt(message)?;
                    
                    self.session_timestamps
                        .write()
                        .await
                        .insert(message.session_id.clone(), Instant::now());

                    let mut stats = self.stats.write().await;
                    stats.total_messages_decrypted += 1;

                    Ok((session.session_id().to_string(), plaintext))
                } else {
                    let mut stats = self.stats.write().await;
                    stats.session_creations_failed += 1;
                    
                    Err(CryptoError::SessionError(
                        "Session not found".to_string(),
                    ))
                }
            }
            _ => Err(CryptoError::InvalidMessage("Unknown message type".to_string())),
        }
    }

    pub async fn encrypt(&self, session_id: &str, plaintext: &[u8]) -> CryptoResult<SessionMessage> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| CryptoError::SessionError("Session not found".to_string()))?;
        
        let message = session.encrypt(plaintext)?;
        
        drop(sessions);
        
        self.session_timestamps
            .write()
            .await
            .insert(session_id.to_string(), Instant::now());

        let mut stats = self.stats.write().await;
        stats.total_messages_encrypted += 1;

        Ok(message)
    }

    pub async fn decrypt(&self, session_id: &str, message: &SessionMessage) -> CryptoResult<Vec<u8>> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| CryptoError::SessionError("Session not found".to_string()))?;
        
        let plaintext = session.decrypt(message)?;
        
        drop(sessions);
        
        self.session_timestamps
            .write()
            .await
            .insert(session_id.to_string(), Instant::now());

        let mut stats = self.stats.write().await;
        stats.total_messages_decrypted += 1;

        Ok(plaintext)
    }

    pub async fn get_session_state(&self, session_id: &str) -> CryptoResult<SessionState> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(session_id)
            .ok_or_else(|| CryptoError::SessionError("Session not found".to_string()))?;
        Ok(session.state())
    }

    pub async fn restore_session(&self, state: SessionState) -> CryptoResult<String> {
        let session = Session::from_state(state);
        let session_id = session.session_id().to_string();
        
        self.sessions
            .write()
            .await
            .insert(session_id.clone(), session);
        
        self.session_timestamps
            .write()
            .await
            .insert(session_id.clone(), Instant::now());

        let mut stats = self.stats.write().await;
        stats.active_sessions += 1;

        Ok(session_id)
    }

    pub async fn remove_session(&self, session_id: &str) -> CryptoResult<()> {
        self.sessions.write().await.remove(session_id);
        self.session_timestamps.write().await.remove(session_id);
        
        let mut stats = self.stats.write().await;
        stats.active_sessions = stats.active_sessions.saturating_sub(1);
        
        info!("Removed session: {}", session_id);
        Ok(())
    }

    pub async fn cleanup_expired_sessions(&self) -> usize {
        let now = Instant::now();
        let mut expired = Vec::new();
        
        let timestamps = self.session_timestamps.read().await;
        for (session_id, timestamp) in timestamps.iter() {
            if now.duration_since(*timestamp).as_secs() > SESSION_EXPIRY_SECS {
                expired.push(session_id.clone());
            }
        }
        drop(timestamps);

        for session_id in &expired {
            self.sessions.write().await.remove(session_id);
            self.session_timestamps.write().await.remove(session_id);
        }

        let mut stats = self.stats.write().await;
        stats.active_sessions = stats.active_sessions.saturating_sub(expired.len());

        if !expired.is_empty() {
            info!("Cleaned up {} expired sessions", expired.len());
        }

        expired.len()
    }

    pub async fn get_active_session_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    pub async fn stats(&self) -> SessionStatsSnapshot {
        let stats = self.stats.read().await;
        SessionStatsSnapshot {
            active_sessions: stats.active_sessions,
            total_sessions_created: stats.total_sessions_created,
            total_messages_encrypted: stats.total_messages_encrypted,
            total_messages_decrypted: stats.total_messages_decrypted,
            session_creations_failed: stats.session_creations_failed,
            otk_count: self.get_otk_count().await,
        }
    }

    pub fn identity_public(&self) -> [u8; 32] {
        self.local_identity.identity_public
    }

    pub fn identity_public_base64(&self) -> String {
        base64_encode(self.local_identity.identity_public)
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

fn base64_encode(data: [u8; 32]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(data)
}

#[derive(Debug, Clone)]
pub struct SessionStatsSnapshot {
    pub active_sessions: usize,
    pub total_sessions_created: usize,
    pub total_messages_encrypted: u64,
    pub total_messages_decrypted: u64,
    pub session_creations_failed: u64,
    pub otk_count: usize,
}

pub struct SecureTransport<T> {
    inner: T,
    session_manager: Arc<SessionManager>,
    active_sessions: RwLock<HashMap<String, String>>,
    enabled: bool,
    e2ee_required: bool,
}

impl<T> SecureTransport<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            session_manager: Arc::new(SessionManager::new()),
            active_sessions: RwLock::new(HashMap::new()),
            enabled: true,
            e2ee_required: false,
        }
    }

    pub fn with_session_manager(inner: T, session_manager: Arc<SessionManager>) -> Self {
        Self {
            inner,
            session_manager,
            active_sessions: RwLock::new(HashMap::new()),
            enabled: true,
            e2ee_required: false,
        }
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_e2ee_required(&mut self, required: bool) {
        self.e2ee_required = required;
    }

    pub fn is_e2ee_required(&self) -> bool {
        self.e2ee_required
    }

    pub fn session_manager(&self) -> &Arc<SessionManager> {
        &self.session_manager
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    pub async fn initialize(&self) -> CryptoResult<()> {
        self.session_manager.initialize().await
    }

    pub async fn establish_session(
        &self,
        peer_identity: [u8; 32],
        peer_bundle: &PreKeyBundle,
    ) -> CryptoResult<String> {
        if !self.enabled {
            return Err(CryptoError::SessionError("E2EE not enabled".to_string()));
        }

        let (session_id, message) = self
            .session_manager
            .create_session_initiator(peer_identity, peer_bundle)
            .await?;

        self.active_sessions
            .write()
            .await
            .insert(peer_identity_to_string(peer_identity), session_id.clone());

        debug!("Established secure session: {}", session_id);
        Ok(session_id)
    }

    pub async fn get_session_for_peer(&self, peer_identity: [u8; 32]) -> Option<String> {
        self.active_sessions
            .read()
            .await
            .get(&peer_identity_to_string(peer_identity))
            .cloned()
    }

    pub async fn encrypt_for_peer(
        &self,
        peer_identity: [u8; 32],
        plaintext: &[u8],
    ) -> CryptoResult<SessionMessage> {
        if !self.enabled {
            return Err(CryptoError::SessionError("E2EE not enabled".to_string()));
        }

        let session_id = self
            .get_session_for_peer(peer_identity)
            .await
            .ok_or_else(|| CryptoError::SessionError("No session with peer".to_string()))?;

        self.session_manager.encrypt(&session_id, plaintext).await
    }

    pub async fn decrypt(&self, message: &SessionMessage) -> CryptoResult<Vec<u8>> {
        if !self.enabled {
            return Err(CryptoError::SessionError("E2EE not enabled".to_string()));
        }

        self.session_manager.decrypt(&message.session_id, message).await
    }

    pub async fn decrypt_from_peer(
        &self,
        peer_identity: [u8; 32],
        message: &SessionMessage,
    ) -> CryptoResult<Vec<u8>> {
        if !self.enabled {
            return Err(CryptoError::SessionError("E2EE not enabled".to_string()));
        }

        let session_id = self
            .get_session_for_peer(peer_identity)
            .await
            .ok_or_else(|| CryptoError::SessionError("No session with peer".to_string()))?;

        self.session_manager.decrypt(&session_id, message).await
    }

    pub async fn remove_session(&self, peer_identity: [u8; 32]) -> CryptoResult<()> {
        if let Some(session_id) = self.get_session_for_peer(peer_identity).await {
            self.session_manager.remove_session(&session_id).await?;
            self.active_sessions
                .write()
                .await
                .remove(&peer_identity_to_string(peer_identity));
        }
        Ok(())
    }

    pub async fn active_peer_count(&self) -> usize {
        self.active_sessions.read().await.len()
    }
}

fn peer_identity_to_string(identity: [u8; 32]) -> String {
    hex::encode(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_manager() {
        let manager = SessionManager::new();
        manager.generate_one_time_keys(10).await.unwrap();

        let bundle = manager.get_prekey_bundle().await.unwrap();
        assert_eq!(bundle.identity_key, manager.identity_public());
    }

    #[tokio::test]
    async fn test_secure_transport() {
        let inner = "test-transport";
        let secure = SecureTransport::new(inner);

        assert!(secure.is_enabled());
        secure.session_manager().generate_one_time_keys(5).await.unwrap();
    }

    #[tokio::test]
    async fn test_session_stats() {
        let manager = SessionManager::new();
        manager.initialize().await.unwrap();

        let stats = manager.stats().await;
        assert_eq!(stats.active_sessions, 0);
        assert!(stats.otk_count > 0);
    }
}
