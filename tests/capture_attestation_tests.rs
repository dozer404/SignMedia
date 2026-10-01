use anyhow::Result;
use signmedia::capture::{
    verify_attestation_statement, AssuranceLevel, CaptureAttestor, SoftwareKeyAttestor,
};
use signmedia::crypto::generate_keypair;

#[test]
fn test_capture_attestation_verification_and_tamper_protection() -> Result<()> {
    let keypair = generate_keypair();
    let attestor = SoftwareKeyAttestor::new(keypair, "device_001".to_string());

    let media = b"sample photo payload";
    let nonce = "nonce_12345";

    let statement = attestor.attest(media, nonce)?;

    // Valid statement verifies
    assert!(verify_attestation_statement(&statement, media)?);

    // Editing device_id invalidates signature (R08)
    let mut tampered_device = statement.clone();
    tampered_device.device_id = "device_999".to_string();
    assert!(!verify_attestation_statement(&tampered_device, media)?);

    // Editing assurance_level invalidates signature (R08)
    let mut tampered_assurance = statement.clone();
    tampered_assurance.assurance_level = AssuranceLevel::AttestedPipeline;
    assert!(!verify_attestation_statement(&tampered_assurance, media)?);

    Ok(())
}
