use signmedia::trust::{
    evaluate_historical_status, EvidenceStatus, RevocationRecord,
};
use chrono::{Duration, Utc};

#[test]
fn test_historical_revocation_evaluation() {
    let now = Utc::now();
    let past_sig_time = now - Duration::days(10);
    let revocation_time = now - Duration::days(5);
    let future_sig_time = now - Duration::days(2);

    let record = RevocationRecord {
        key_or_asset_id: "key_1".to_string(),
        revoked_at: revocation_time,
        reason: "Key compromise".to_string(),
    };

    // Signature before revocation is historically good
    assert_eq!(
        evaluate_historical_status(past_sig_time, Some(&record)),
        EvidenceStatus::Good
    );

    // Signature after revocation is revoked
    assert_eq!(
        evaluate_historical_status(future_sig_time, Some(&record)),
        EvidenceStatus::Revoked
    );

    // No revocation record is unknown / unavailable (absence of evidence != good status)
    assert_eq!(
        evaluate_historical_status(future_sig_time, None),
        EvidenceStatus::Unknown
    );
}
