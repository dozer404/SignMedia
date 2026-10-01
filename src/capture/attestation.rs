use anyhow::Result;
use serde::{Deserialize, Serialize};
use ed25519_dalek::{Signature, SigningKey, Signer};
use crate::crypto::{hash_data, verify_signature};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssuranceLevel {
    SoftwareKey,
    HardwareKey,
    AttestedPipeline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationStatement {
    pub device_id: String,
    pub assurance_level: AssuranceLevel,
    pub challenge_nonce: String,
    pub signature: String, // Hex
    pub public_key: String, // Hex
}

pub trait CaptureAttestor {
    fn assurance_level(&self) -> AssuranceLevel;
    fn attest(&self, media_data: &[u8], challenge_nonce: &str) -> Result<AttestationStatement>;
}

pub struct SoftwareKeyAttestor {
    signing_key: SigningKey,
    device_id: String,
}

impl SoftwareKeyAttestor {
    pub fn new(signing_key: SigningKey, device_id: String) -> Self {
        Self {
            signing_key,
            device_id,
        }
    }
}

impl CaptureAttestor for SoftwareKeyAttestor {
    fn assurance_level(&self) -> AssuranceLevel {
        AssuranceLevel::SoftwareKey
    }

    fn attest(&self, media_data: &[u8], challenge_nonce: &str) -> Result<AttestationStatement> {
        let media_hash = hash_data(media_data);
        let mut commitment = Vec::new();
        commitment.extend_from_slice(&media_hash);
        commitment.extend_from_slice(challenge_nonce.as_bytes());

        let sig = self.signing_key.sign(&commitment);
        let pub_key_hex = hex::encode(self.signing_key.verifying_key().to_bytes());

        Ok(AttestationStatement {
            device_id: self.device_id.clone(),
            assurance_level: self.assurance_level(),
            challenge_nonce: challenge_nonce.to_string(),
            signature: hex::encode(sig.to_bytes()),
            public_key: pub_key_hex,
        })
    }
}

pub struct SimulatedHardwareAttestor {
    signing_key: SigningKey,
    device_id: String,
}

impl SimulatedHardwareAttestor {
    pub fn new(signing_key: SigningKey, device_id: String) -> Self {
        Self {
            signing_key,
            device_id,
        }
    }
}

impl CaptureAttestor for SimulatedHardwareAttestor {
    fn assurance_level(&self) -> AssuranceLevel {
        AssuranceLevel::HardwareKey
    }

    fn attest(&self, media_data: &[u8], challenge_nonce: &str) -> Result<AttestationStatement> {
        let media_hash = hash_data(media_data);
        let mut commitment = Vec::new();
        commitment.extend_from_slice(&media_hash);
        commitment.extend_from_slice(challenge_nonce.as_bytes());

        let sig = self.signing_key.sign(&commitment);
        let pub_key_hex = hex::encode(self.signing_key.verifying_key().to_bytes());

        Ok(AttestationStatement {
            device_id: self.device_id.clone(),
            assurance_level: self.assurance_level(),
            challenge_nonce: challenge_nonce.to_string(),
            signature: hex::encode(sig.to_bytes()),
            public_key: pub_key_hex,
        })
    }
}

pub fn verify_attestation_statement(
    statement: &AttestationStatement,
    media_data: &[u8],
) -> Result<bool> {
    let media_hash = hash_data(media_data);
    let mut commitment = Vec::new();
    commitment.extend_from_slice(&media_hash);
    commitment.extend_from_slice(statement.challenge_nonce.as_bytes());

    let pub_key_bytes = hex::decode(&statement.public_key)?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
        &pub_key_bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid key length"))?
    )?;

    let sig_bytes = hex::decode(&statement.signature)?;
    let signature = Signature::from_bytes(
        &sig_bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid sig length"))?
    );

    Ok(verify_signature(&commitment, &signature, &verifying_key))
}
