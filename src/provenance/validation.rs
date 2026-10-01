use crate::crypto::{hash_data, verify_signature};
use crate::models::SignedManifest;
use crate::provenance::types::{
    IntegrityStatus, LineageStatus, TimestampStatus, TrustStatus, ValidationReport,
};
use ed25519_dalek::VerifyingKey;

pub fn validate_signed_manifest(manifest: &SignedManifest) -> ValidationReport {
    let mut report = ValidationReport::default();

    if manifest.signatures.is_empty() {
        report.content_integrity = IntegrityStatus::Absent;
        report.details.push("No signatures present".to_string());
        return report;
    }

    let content_json = match serde_json::to_vec(&manifest.content) {
        Ok(json) => json,
        Err(e) => {
            report.content_integrity = IntegrityStatus::Invalid;
            report.details.push(format!("Failed to serialize manifest content: {}", e));
            return report;
        }
    };

    let content_hash = hash_data(&content_json);
    let mut valid_sig_found = false;

    for sig_entry in &manifest.signatures {
        let pub_key_bytes = match hex::decode(&sig_entry.public_key) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };

        let verifying_key = match pub_key_bytes.as_slice().try_into().map(VerifyingKey::from_bytes) {
            Ok(Ok(vk)) => vk,
            _ => continue,
        };

        let sig_bytes = match hex::decode(&sig_entry.signature) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };

        let signature = match sig_bytes.as_slice().try_into().map(ed25519_dalek::Signature::from_bytes) {
            Ok(sig) => sig,
            Err(_) => continue,
        };

        if verify_signature(&content_hash, &signature, &verifying_key) {
            valid_sig_found = true;
            break;
        }
    }

    if valid_sig_found {
        report.content_integrity = IntegrityStatus::Verified;
        report.signer_trust = TrustStatus::Trusted; // Default local trust for valid legacy keys
        report.timestamp_status = TimestampStatus::Valid;
        report.lineage_status = LineageStatus::Complete;
    } else {
        report.content_integrity = IntegrityStatus::Invalid;
        report.signer_trust = TrustStatus::Untrusted;
        report.details.push("Cryptographic signature verification failed".to_string());
    }

    report
}
