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

    let token = Rfc3161TimestampToken {
        tsa_name: "SignMedia TSA".to_string(),
        timestamp: Utc::now(),
        message_imprint: hex::encode(data_hash),
        raw_token_b64: "token_bytes".to_string(),
    };

    assert!(verify_timestamp_imprint(&token, data)?);
    assert!(validate_timestamp_evidence(
        Some(&token),
        data,
        TsaRequirementMode::Required
    )?);

    let tampered_data = b"tampered media data";
    assert!(!verify_timestamp_imprint(&token, tampered_data)?);

    // Test missing token under Required vs Optional mode
    assert!(validate_timestamp_evidence(None, data, TsaRequirementMode::Optional)?);
    assert!(validate_timestamp_evidence(None, data, TsaRequirementMode::Required).is_err());

    Ok(())
}
