use signmedia::trust::{
    evaluate_notary_requirement, TrustAnchorConfig, VerificationPolicy,
};

#[test]
fn test_legacy_v0_policy_requires_notary() {
    let config = TrustAnchorConfig::default();
    assert!(evaluate_notary_requirement(
        VerificationPolicy::LegacyV0,
        &config,
        true
    ));
    assert!(!evaluate_notary_requirement(
        VerificationPolicy::LegacyV0,
        &config,
        false
    ));
}

#[test]
fn test_configurable_v2_policy_optional_notary() {
    let mut config = TrustAnchorConfig::default();
    config.require_notary_cosignature = false;

    // Optional notary co-signature allowed when not required
    assert!(evaluate_notary_requirement(
        VerificationPolicy::ConfigurableV2,
        &config,
        false
    ));
    assert!(evaluate_notary_requirement(
        VerificationPolicy::ConfigurableV2,
        &config,
        true
    ));

    // When required, missing notary fails
    config.require_notary_cosignature = true;
    assert!(!evaluate_notary_requirement(
        VerificationPolicy::ConfigurableV2,
        &config,
        false
    ));
}
