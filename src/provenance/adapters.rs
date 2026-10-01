use crate::models::{ManifestContent, SignedManifest};
use crate::provenance::types::{Asset, Claim};

pub fn manifest_to_asset(manifest: &SignedManifest) -> Asset {
    match &manifest.content {
        ManifestContent::Original(owd) => Asset {
            id: owd.work_id.to_string(),
            title: Some(owd.title.clone()),
            claims: owd
                .authors
                .iter()
                .map(|author| Claim {
                    claim_type: "authorship".to_string(),
                    actor_id: author.author_id.clone(),
                    signature: manifest.signatures.first().map(|s| s.signature.clone()),
                })
                .collect(),
        },
        ManifestContent::Derivative(dwd) => Asset {
            id: dwd.derivative_id.to_string(),
            title: Some(dwd.original_owd.title.clone()),
            claims: vec![Claim {
                claim_type: "derivation".to_string(),
                actor_id: dwd.clipper_id.clone(),
                signature: manifest.signatures.first().map(|s| s.signature.clone()),
            }],
        },
    }
}
