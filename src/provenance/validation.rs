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
    let mut all_sigs_valid = true;
    let mut verified_keys = Vec::new();

    for sig_entry in &manifest.signatures {
        let pub_key_bytes = match hex::decode(&sig_entry.public_key) {
            Ok(bytes) => bytes,
            Err(_) => {
                all_sigs_valid = false;
                report.details.push(format!("Malformed public key hex: {}", sig_entry.public_key));
                continue;
            }
        };

        let verifying_key = match pub_key_bytes.as_slice().try_into().map(VerifyingKey::from_bytes) {
            Ok(Ok(vk)) => vk,
            _ => {
                all_sigs_valid = false;
                report.details.push("Invalid verifying key size or format".to_string());
                continue;
            }
        };

        let sig_bytes = match hex::decode(&sig_entry.signature) {
            Ok(bytes) => bytes,
            Err(_) => {
                all_sigs_valid = false;
                report.details.push("Malformed signature hex".to_string());
                continue;
            }
        };

        let signature = match sig_bytes.as_slice().try_into().map(ed25519_dalek::Signature::from_bytes) {
            Ok(sig) => sig,
            _ => {
                all_sigs_valid = false;
                report.details.push("Invalid signature size or format".to_string());
                continue;
            }
        };

        if verify_signature(&content_hash, &signature, &verifying_key) {
            verified_keys.push(sig_entry.public_key.clone());
        } else {
            all_sigs_valid = false;
            report.details.push(format!("Signature verification failed for key {}", sig_entry.public_key));
        }
    }

    if all_sigs_valid && !verified_keys.is_empty() {
        report.content_integrity = IntegrityStatus::Verified;
        report.signer_trust = TrustStatus::Trusted;
        report.timestamp_status = TimestampStatus::Absent;
        report.lineage_status = match &manifest.content {
            crate::models::ManifestContent::Original(_) => LineageStatus::Complete,
            crate::models::ManifestContent::Derivative(dwd) => {
                if dwd.clip_mappings.is_empty() {
                    LineageStatus::Incomplete
                } else {
                    LineageStatus::Complete
                }
            }
        };
    } else {
        report.content_integrity = IntegrityStatus::Invalid;
        report.signer_trust = TrustStatus::Untrusted;
        report.timestamp_status = TimestampStatus::Absent;
        report.lineage_status = LineageStatus::Broken;
    }

    report
}
