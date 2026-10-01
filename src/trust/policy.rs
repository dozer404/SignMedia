use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationPolicy {
    /// Legacy v0/v1 policy requiring mandatory Trusted Third Party (TTP) co-signature
    LegacyV0,
    /// Configurable credential policy where TTP co-signing is optional
    ConfigurableV2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAnchorConfig {
    pub allow_untrusted_roots: bool,
    pub require_notary_cosignature: bool,
    pub trusted_signer_certs: Vec<String>, // PEM strings
    pub trusted_tsa_certs: Vec<String>,    // PEM strings
}

impl Default for TrustAnchorConfig {
    fn default() -> Self {
        Self {
            allow_untrusted_roots: true,
            require_notary_cosignature: false,
            trusted_signer_certs: Vec::new(),
            trusted_tsa_certs: Vec::new(),
        }
    }
}

pub fn evaluate_notary_requirement(
    policy: VerificationPolicy,
    config: &TrustAnchorConfig,
    has_notary_signature: bool,
) -> bool {
    match policy {
        VerificationPolicy::LegacyV0 => has_notary_signature,
        VerificationPolicy::ConfigurableV2 => {
            if config.require_notary_cosignature {
                has_notary_signature
            } else {
                true
            }
        }
    }
}
