use crate::crypto::hash_to_scalar;
use anyhow::{Context, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum InviteError {
    #[error("Invalid threshold: k must be <= n")]
    InvalidThreshold,
    #[error("Insufficient shares: need {0} shares to reconstruct")]
    InsufficientShares(usize),
    #[error("Invalid share: share verification failed")]
    InvalidShare,
    #[error("Invite expired")]
    InviteExpired,
    #[error("Invite already used")]
    InviteAlreadyUsed,
    #[error("Invalid invite token")]
    InvalidToken,
    #[error("VSS verification failed")]
    VssVerificationFailed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invite {
    pub invite_id: Uuid,
    pub circle_id: Uuid,
    pub threshold: u8,
    pub total_shares: u8,
    pub shares: Vec<InviteShare>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub max_uses: Option<u32>,
    pub uses: u32,
    pub issuer_id: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InviteShare {
    pub share_id: u8,
    pub share_value: [u8; 32],
    pub commitment: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InviteToken {
    pub invite_id: Uuid,
    pub circle_id: Uuid,
    pub share_id: u8,
    pub share_value: [u8; 32],
    pub signature: [u8; 64],
    pub issuer_public_key: [u8; 32],
}

pub struct ShamirSecretSharing {
    prime: [u8; 32],
}

impl ShamirSecretSharing {
    pub fn new() -> Self {
        let prime = Self::large_prime();
        Self { prime }
    }

    fn large_prime() -> [u8; 32] {
        let p: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F.into();
        let mut bytes = [0u8; 32];
        let (_lo, hi) = p.0.split_at(16);
        bytes[..16].copy_from_slice(&[0u8; 16]);
        bytes[16..].copy_from_slice(hi);
        bytes
    }

    fn bytes_to_field(&self, bytes: &[u8]) -> u256 {
        let mut padded = [0u8; 32];
        let len = bytes.len().min(32);
        padded[32 - len..].copy_from_slice(&bytes[..len]);
        u256::from_le_bytes(padded) % u256::from_le_bytes(self.prime)
    }

    fn field_to_bytes(&self, value: u256) -> [u8; 32] {
        let v = value % u256::from_le_bytes(self.prime);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&v.0[..32]);
        bytes
    }

    fn add(&self, a: u256, b: u256) -> u256 {
        (a + b) % u256::from_le_bytes(self.prime)
    }

    fn sub(&self, a: u256, b: u256) -> u256 {
        (a + u256::from_le_bytes(self.prime) - b) % u256::from_le_bytes(self.prime)
    }

    fn mul(&self, a: u256, b: u256) -> u256 {
        (a * b) % u256::from_le_bytes(self.prime)
    }

    fn pow(&self, base: u256, exp: u256) -> u256 {
        let mut result = u256::from(1u64);
        let mut base = base;
        let mut exp = exp;
        while exp > 0 {
            if exp & 1 == 1 {
                result = self.mul(result, base);
            }
            base = self.mul(base, base);
            exp >>= 1;
        }
        result
    }

    pub fn split_secret(&self, secret: &[u8], threshold: u8, num_shares: u8) -> Result<Vec<InviteShare>, InviteError> {
        if threshold > num_shares || threshold == 0 || num_shares == 0 {
            return Err(InviteError::InvalidThreshold);
        }

        let secret_field = self.bytes_to_field(secret);
        let mut coefficients = vec![secret_field];
        let mut rng = rand::thread_rng();

        for _ in 1..threshold {
            let mut coeff_bytes = [0u8; 32];
            rng.fill_bytes(&mut coeff_bytes);
            coefficients.push(self.bytes_to_field(&coeff_bytes));
        }

        let mut shares = Vec::with_capacity(num_shares as usize);
        let generator = u256::from(2u64);

        for x in 1..=num_shares as u64 {
            let mut y = secret_field;
            let x_field = u256::from(x);

            for (i, coeff) in coefficients.iter().enumerate().skip(1) {
                let term = self.mul(*coeff, self.pow(x_field, i as u64));
                y = self.add(y, term);
            }

            let share_value = self.field_to_bytes(y);
            let commitment = self.compute_commitment(coefficients[0], generator);

            shares.push(InviteShare {
                share_id: x as u8,
                share_value,
                commitment,
            });
        }

        Ok(shares)
    }

    fn compute_commitment(&self, value: u256, generator: u256) -> [u8; 32] {
        let committed = self.pow(generator, value);
        self.field_to_bytes(committed)
    }

    pub fn verify_share(&self, share: &InviteShare, generator: u256) -> bool {
        let mut lhs = u256::from(2u64);
        for i in 1..share.share_id as u64 {
            lhs = self.mul(lhs, generator);
        }

        let mut expected = self.bytes_to_field(&share.commitment);
        let share_value = self.bytes_to_field(&share.share_value);

        lhs == expected || self.verify_share_vss(share, generator)
    }

    fn verify_share_vss(&self, share: &InviteShare, generator: u256) -> bool {
        let g = generator;
        let x = u256::from(share.share_id);
        let y = self.bytes_to_field(&share.share_value);
        let commitment = self.bytes_to_field(&share.commitment);

        let left = self.pow(g, y);
        let right = commitment;

        left == right
    }

    pub fn reconstruct_secret(&self, shares: &[InviteShare]) -> Result<[u8; 32], InviteError> {
        if shares.is_empty() {
            return Err(InviteError::InsufficientShares(1));
        }

        let threshold = shares.len();
        if threshold < 2 {
            return Ok(shares[0].share_value);
        }

        let mut secret = u256::from(0u64);

        for i in 0..threshold {
            let xi = u256::from(shares[i].share_id);
            let yi = self.bytes_to_field(&shares[i].share_value);

            let mut numerator = u256::from(1u64);
            let mut denominator = u256::from(1u64);

            for j in 0..threshold {
                if i != j {
                    let xj = u256::from(shares[j].share_id);
                    numerator = self.mul(numerator, self.sub(u256::from(0u64), xj));
                    denominator = self.mul(denominator, self.sub(xi, xj));
                }
            }

            let lagrange_coeff = self.mul(
                numerator,
                self.pow(denominator, u256::from_le_bytes(self.prime) - 2),
            );
            secret = self.add(secret, self.mul(yi, lagrange_coeff));
        }

        Ok(self.field_to_bytes(secret))
    }
}

impl Default for ShamirSecretSharing {
    fn default() -> Self {
        Self::new()
    }
}

pub struct FeldmanVss {
    generator: u256,
    prime: [u8; 32],
}

impl FeldmanVss {
    pub fn new() -> Self {
        let prime: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F.into();
        Self {
            generator: u256::from(2u64),
            prime,
        }
    }

    pub fn create_commitments(&self, secret: &[u8], threshold: u8) -> Result<(Vec<[u8; 32]>, [u8; 32]), InviteError> {
        let mut rng = rand::thread_rng();
        let secret_field = self.bytes_to_field(secret);
        let mut coefficients = vec![secret_field];

        for _ in 1..threshold {
            let mut coeff_bytes = [0u8; 32];
            rng.fill_bytes(&mut coeff_bytes);
            coefficients.push(self.bytes_to_field(&coeff_bytes));
        }

        let mut commitments = Vec::with_capacity(threshold as usize);
        for coeff in &coefficients {
            let commitment = self.pow(*coeff);
            commitments.push(self.field_to_bytes(commitment));
        }

        let secret_commitment = commitments[0];
        Ok((commitments, secret_commitment))
    }

    pub fn verify_share(&self, share_id: u8, share_value: &[u8], commitments: &[[u8; 32]]) -> bool {
        let x = u256::from(share_id);
        let y = self.bytes_to_field(share_value);

        let mut lhs = self.pow(y);
        
        let mut rhs = commitments[0];
        for (i, commitment) in commitments.iter().enumerate().skip(1) {
            let term = self.mul(self.bytes_to_field(commitment), self.pow(x, i as u64));
            rhs = self.add(rhs, term);
        }

        lhs == rhs
    }

    fn bytes_to_field(&self, bytes: &[u8]) -> u256 {
        let mut padded = [0u8; 32];
        let len = bytes.len().min(32);
        padded[32 - len..].copy_from_slice(&bytes[..len]);
        u256::from_le_bytes(padded) % u256::from_le_bytes(self.prime)
    }

    fn field_to_bytes(&self, value: u256) -> [u8; 32] {
        let v = value % u256::from_le_bytes(self.prime);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&v.0[..32]);
        bytes
    }

    fn add(&self, a: u256, b: u256) -> u256 {
        (a + b) % u256::from_le_bytes(self.prime)
    }

    fn mul(&self, a: u256, b: u256) -> u256 {
        (a * b) % u256::from_le_bytes(self.prime)
    }

    fn pow(&self, base: u256) -> u256 {
        self.pow_with_exp(base, u256::from(2u64))
    }

    fn pow_with_exp(&self, base: u256, exp: u256) -> u256 {
        let mut result = u256::from(1u64);
        let mut base = base;
        let mut exp = exp;
        let prime = u256::from_le_bytes(self.prime);
        while exp > 0 {
            if exp & 1 == 1 {
                result = self.mul(result, base);
            }
            base = self.mul(base, base);
            exp >>= 1;
        }
        result
    }
}

impl Default for FeldmanVss {
    fn default() -> Self {
        Self::new()
    }
}

pub struct InviteManager {
    invites: HashMap<Uuid, Invite>,
    pending_joins: HashMap<Uuid, Vec<[u8; 32]>>,
}

impl InviteManager {
    pub fn new() -> Self {
        Self {
            invites: HashMap::new(),
            pending_joins: HashMap::new(),
        }
    }

    pub fn create_invite(
        &mut self,
        circle_id: Uuid,
        threshold: u8,
        num_shares: u8,
        issuer_id: Uuid,
        max_uses: Option<u32>,
        validity_duration: chrono::Duration,
    ) -> Result<Invite, InviteError> {
        let sss = ShamirSecretSharing::new();
        let secret = {
            let mut rng = rand::thread_rng();
            let mut secret = [0u8; 32];
            rng.fill_bytes(&mut secret);
            secret
        };

        let shares = sss.split_secret(&secret, threshold, num_shares)?;

        let now = chrono::Utc::now();
        let invite = Invite {
            invite_id: Uuid::new_v4(),
            circle_id,
            threshold,
            total_shares: num_shares,
            shares,
            created_at: now,
            expires_at: now + validity_duration,
            max_uses,
            uses: 0,
            issuer_id,
        };

        self.invites.insert(invite.invite_id, invite.clone());
        self.pending_joins.insert(invite.invite_id, Vec::new());

        Ok(invite)
    }

    pub fn get_invite(&self, invite_id: Uuid) -> Option<&Invite> {
        self.invites.get(&invite_id)
    }

    pub fn validate_token(&self, token: &InviteToken) -> Result<Invite, InviteError> {
        let invite = self
            .invites
            .get(&token.invite_id)
            .ok_or(InviteError::InvalidToken)?;

        if chrono::Utc::now() > invite.expires_at {
            return Err(InviteError::InviteExpired);
        }

        if let Some(max) = invite.max_uses {
            if invite.uses >= max {
                return Err(InviteError::InviteAlreadyUsed);
            }
        }

        let share = invite
            .shares
            .iter()
            .find(|s| s.share_id == token.share_id)
            .ok_or(InviteError::InvalidToken)?;

        if share.share_value != token.share_value {
            return Err(InviteError::InvalidShare);
        }

        Ok(invite.clone())
    }

    pub fn register_share(&mut self, invite_id: Uuid, member_id: Uuid, share: [u8; 32]) -> Result<bool, InviteError> {
        let pending = self.pending_joins.entry(invite_id).or_insert_with(Vec::new);
        
        if pending.contains(&member_id.to_bytes()) {
            return Err(InviteError::InviteAlreadyUsed);
        }

        pending.push(member_id.to_bytes());

        let invite = self.invites.get(&invite_id).ok_or(InviteError::InvalidToken)?;
        let shares_needed = invite.threshold as usize;

        if pending.len() >= shares_needed {
            return Ok(true);
        }

        Ok(false)
    }

    pub fn use_invite(&mut self, invite_id: Uuid) -> Result<(), InviteError> {
        let invite = self.invites.get_mut(&invite_id).ok_or(InviteError::InvalidToken)?;
        invite.uses += 1;

        if let Some(max) = invite.max_uses {
            if invite.uses >= max {
                self.invites.remove(&invite_id);
                self.pending_joins.remove(&invite_id);
            }
        }

        Ok(())
    }

    pub fn revoke_invite(&mut self, invite_id: Uuid) -> Result<(), InviteError> {
        self.invites
            .remove(&invite_id)
            .ok_or(InviteError::InvalidToken)?;
        self.pending_joins.remove(&invite_id);
        Ok(())
    }

    pub fn list_active_invites(&self, circle_id: Uuid) -> Vec<Uuid> {
        self.invites
            .values()
            .filter(|i| i.circle_id == circle_id && chrono::Utc::now() <= i.expires_at)
            .map(|i| i.invite_id)
            .collect()
    }
}

impl Default for InviteManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
struct u256(pub [u8; 32]);

impl u256 {
    fn from(x: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&x.to_le_bytes());
        Self(bytes)
    }

    fn from_le_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn to_le_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl std::ops::Add for u256 {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        let a = u128::from_le_bytes(self.0[16..].try_into()
            .expect("slice [16..] of [u8; 32] is always 16 bytes")) 
            | (u128::from_le_bytes(self.0[..16].try_into()
                .expect("slice [..16] of [u8; 32] is always 16 bytes")) << 128);
        let b = u128::from_le_bytes(other.0[16..].try_into()
            .expect("slice [16..] of [u8; 32] is always 16 bytes"))
            | (u128::from_le_bytes(other.0[..16].try_into()
                .expect("slice [..16] of [u8; 32] is always 16 bytes")) << 128);
        let sum = a.wrapping_add(b);
        let mut result = [0u8; 32];
        result[..16].copy_from_slice(&(sum as u128).to_le_bytes());
        result[16..].copy_from_slice(&((sum >> 128) as u128).to_le_bytes());
        Self(result)
    }
}

impl std::ops::Sub for u256 {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        let a = u128::from_le_bytes(self.0[16..].try_into()
            .expect("slice [16..] of [u8; 32] is always 16 bytes"))
            | (u128::from_le_bytes(self.0[..16].try_into()
                .expect("slice [..16] of [u8; 32] is always 16 bytes")) << 128);
        let b = u128::from_le_bytes(other.0[16..].try_into()
            .expect("slice [16..] of [u8; 32] is always 16 bytes"))
            | (u128::from_le_bytes(other.0[..16].try_into()
                .expect("slice [..16] of [u8; 32] is always 16 bytes")) << 128);
        let diff = a.wrapping_sub(b);
        let mut result = [0u8; 32];
        result[..16].copy_from_slice(&(diff as u128).to_le_bytes());
        result[16..].copy_from_slice(&((diff >> 128) as u128).to_le_bytes());
        Self(result)
    }
}

impl std::ops::Mul for u256 {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        let a_lo = u128::from_le_bytes(self.0[..16].try_into()
            .expect("slice [..16] of [u8; 32] is always 16 bytes"));
        let a_hi = u128::from_le_bytes(self.0[16..].try_into()
            .expect("slice [16..] of [u8; 32] is always 16 bytes"));
        let b_lo = u128::from_le_bytes(other.0[..16].try_into()
            .expect("slice [..16] of [u8; 32] is always 16 bytes"));
        let b_hi = u128::from_le_bytes(other.0[16..].try_into()
            .expect("slice [16..] of [u8; 32] is always 16 bytes"));

        let (lo, hi) = split_mul(a_lo, a_hi, b_lo, b_hi);
        let mut result = [0u8; 32];
        result[..16].copy_from_slice(&lo.to_le_bytes());
        result[16..].copy_from_slice(&hi.to_le_bytes());
        Self(result)
    }
}

fn split_mul(a_lo: u128, a_hi: u128, b_lo: u128, b_hi: u128) -> (u128, u128) {
    let a = (a_hi << 64) | a_lo;
    let b = (b_hi << 64) | b_lo;
    let product = a.wrapping_mul(b);
    ((product & ((1u128 << 128) - 1)) as u128, (product >> 128) as u128)
}

impl std::ops::Shr<u32> for u256 {
    type Output = Self;
    fn shr(self, shift: u32) -> Self {
        let s = shift as usize;
        let mut result = [0u8; 32];
        if s >= 256 {
            return Self(result);
        }
        let word_shift = s / 128;
        let bit_shift = s % 128;
        
        if word_shift == 0 {
            let lo = u128::from_le_bytes(self.0[16..].try_into()
                .expect("slice [16..] of [u8; 32] is always 16 bytes"));
            let hi = u128::from_le_bytes(self.0[..16].try_into()
                .expect("slice [..16] of [u8; 32] is always 16 bytes"));
            let shifted = (hi << (128 - bit_shift)) | (lo >> bit_shift);
            result[..16].copy_from_slice(&shifted.to_le_bytes());
        }
        Self(result)
    }
}

impl std::ops::Shl<u32> for u256 {
    type Output = Self;
    fn shl(self, shift: u32) -> Self {
        let s = shift as usize;
        let mut result = [0u8; 32];
        if s >= 256 {
            return Self(result);
        }
        let word_shift = s / 128;
        let bit_shift = s % 128;
        
        if word_shift == 0 {
            let lo = u128::from_le_bytes(self.0[16..].try_into()
                .expect("slice [16..] of [u8; 32] is always 16 bytes"));
            let hi = u128::from_le_bytes(self.0[..16].try_into()
                .expect("slice [..16] of [u8; 32] is always 16 bytes"));
            let shifted = (lo << bit_shift) | (hi >> (128 - bit_shift));
            result[16..].copy_from_slice(&shifted.to_le_bytes());
        }
        Self(result)
    }
}

impl std::ops::BitAnd for u256 {
    type Output = Self;
    fn bitand(self, other: Self) -> Self {
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = self.0[i] & other.0[i];
        }
        Self(result)
    }
}

impl std::ops::BitOr for u256 {
    type Output = Self;
    fn bitor(self, other: Self) -> Self {
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = self.0[i] | other.0[i];
        }
        Self(result)
    }
}

impl PartialEq for u256 {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for u256 {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamir_split_and_reconstruct() {
        let sss = ShamirSecretSharing::new();
        let secret = b"my_super_secret_key_1234567890";
        
        let shares = sss
            .split_secret(secret, 3, 5)
            .expect("secret should split into shares");
        assert_eq!(shares.len(), 5);

        let reconstructed = sss
            .reconstruct_secret(&shares[..3])
            .expect("secret should be reconstructed from shares");
        assert_eq!(&reconstructed[..secret.len()], secret);
    }

    #[test]
    fn test_feldman_vss() {
        let vss = FeldmanVss::new();
        let secret = b"test_secret_for_verification";
        
        let (commitments, _) = vss
            .create_commitments(secret, 3)
            .expect("commitments should be created");

        let share = sss_share_for_test(secret, 1);
        let valid = vss.verify_share(1, &share, &commitments);
        assert!(valid);
    }

    fn sss_share_for_test(secret: &[u8], x: u8) -> [u8; 32] {
        let sss = ShamirSecretSharing::new();
        let shares = sss
            .split_secret(secret, 1, 1)
            .expect("secret should split into shares");
        shares[0].share_value
    }

    #[test]
    fn test_invite_lifecycle() {
        let mut manager = InviteManager::new();
        let circle_id = Uuid::new_v4();
        
        let invite = manager.create_invite(
            circle_id,
            2,
            3,
            Uuid::new_v4(),
            Some(5),
            chrono::Duration::hours(24),
        )
        .expect("invite should be created");

        let active = manager.list_active_invites(circle_id);
        assert!(active.contains(&invite.invite_id));
    }
}
