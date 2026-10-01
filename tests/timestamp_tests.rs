use base64::{engine::general_purpose, Engine as _};
use signmedia::crypto::hash_data;
use signmedia::provenance::{
    validate_timestamp_evidence, verify_timestamp_imprint, Rfc3161TimestampToken,
    TsaRequirementMode,
};
use chrono::Utc;

#[test]
fn test_rfc3161_timestamp_imprint_verification() -> anyhow::Result<()> {
    let data = b"sample media data for timestamping";
    let data_hash = hash_data(data);

    let valid_raw_b64 = general_purpose::STANDARD.encode(vec![0xAAu8; 32]);

    let token = Rfc3161TimestampToken {
        tsa_name: "SignMedia TSA".to_string(),
        timestamp: Utc::now(),
        message_imprint: hex::encode(data_hash),
        raw_token_b64: valid_raw_b64,
    };

    assert!(verify_timestamp_imprint(&token, data)?);
    assert!(validate_timestamp_evidence(
        Some(&token),
        data,
        TsaRequirementMode::Required
    )?);

    let tampered_data = b"tampered media data";
    assert!(!verify_timestamp_imprint(&token, tampered_data)?);

    // Test garbage raw_token_b64 rejection (R05)
    let garbage_token = Rfc3161TimestampToken {
        tsa_name: "Fake TSA".to_string(),
        timestamp: Utc::now(),
        message_imprint: hex::encode(data_hash),
        raw_token_b64: "NOT A TOKEN".to_string(),
    };
    assert!(verify_timestamp_imprint(&garbage_token, data).is_err());

    // Test missing token under Required vs Optional mode
    assert!(!validate_timestamp_evidence(None, data, TsaRequirementMode::Optional)?);
    assert!(validate_timestamp_evidence(None, data, TsaRequirementMode::Required).is_err());

    Ok(())
}
