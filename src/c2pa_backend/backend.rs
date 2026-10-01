use anyhow::Result;
use c2pa::{settings::load_settings_from_str, Builder, Reader, SigningAlg};
use serde_json::json;
use std::path::Path;

pub fn c2pa_sign_file(
    input_path: &Path,
    output_path: &Path,
    title: &str,
    author: &str,
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
) -> Result<()> {
    let _ = load_settings_from_str(r#"{"verify": {"verify_trust": false}}"#, "json");

    let manifest_def = json!({
        "claim_generator": "SignMedia/0.1.0",
        "title": title
    });
    let mut builder = Builder::from_json(&manifest_def.to_string())?;

    let actions = json!({
        "actions": [
            {
                "action": "c2pa.created",
                "parameters": {
                    "name": author
                }
            }
        ]
    });

    builder.add_assertion("c2pa.actions", &actions)?;

    let (cert_bytes, key_bytes) = match (cert_path, key_path) {
        (Some(c), Some(k)) => (std::fs::read(c)?, std::fs::read(k)?),
        (Some(_), None) | (None, Some(_)) => {
            return Err(anyhow::anyhow!("Both certificate and private key paths must be provided"));
        }
        (None, None) => {
            if let (Ok(cert_env), Ok(key_env)) = (std::env::var("C2PA_CERT_PATH"), std::env::var("C2PA_KEY_PATH")) {
                (std::fs::read(cert_env)?, std::fs::read(key_env)?)
            } else {
                return Err(anyhow::anyhow!("Signing credentials missing. Provide --cert and --key parameters or set C2PA_CERT_PATH and C2PA_KEY_PATH environment variables."));
            }
        }
    };

    let signer = c2pa::create_signer::from_keys(
        &cert_bytes,
        &key_bytes,
        SigningAlg::Ps256,
        None,
    )?;

    builder.sign_file(signer.as_ref(), input_path, output_path)?;

    Ok(())
}

pub fn c2pa_verify_file(path: &Path) -> Result<String> {
    let _ = load_settings_from_str(r#"{"verify": {"verify_trust": false}}"#, "json");
    let reader = Reader::from_file(path)?;

    if reader.active_manifest().is_none() {
        return Err(anyhow::anyhow!("No active C2PA manifest found in {:?}", path));
    }

    if let Some(statuses) = reader.validation_status() {
        let failures: Vec<String> = statuses
            .iter()
            .filter(|s| {
                let code = s.code();
                !code.ends_with(".validated") && code != "claim.validated" && code != "signing.credential.validated"
            })
            .map(|s| format!("{}: {}", s.code(), s.explanation().unwrap_or("")))
            .collect();

        if !failures.is_empty() {
            return Err(anyhow::anyhow!(
                "C2PA verification failed for {:?}:\n{}",
                path,
                failures.join("\n")
            ));
        }
    }

    Ok(reader.json())
}

pub fn inspect_file(path: &Path) -> Result<String> {
    let _ = load_settings_from_str(r#"{"verify": {"verify_trust": false}}"#, "json");
    let reader = Reader::from_file(path)?;
    let mut output = String::new();
    output.push_str("C2PA Manifest Summary:\n");
    if let Some(active) = reader.active_manifest() {
        let title = active.title().unwrap_or("Untitled");
        output.push_str(&format!("  Title: {}\n", title));
        output.push_str(&format!("  Format: {}\n", active.format()));
        output.push_str(&format!("  Claim Generator: {}\n", active.claim_generator()));
        if let Some(issuer) = active.issuer() {
            output.push_str(&format!("  Issuer: {}\n", issuer));
        }
        if let Some(time) = active.time() {
            output.push_str(&format!("  Time: {}\n", time));
        }
        output.push_str(&format!("  Ingredients: {}\n", active.ingredients().len()));
        output.push_str(&format!("  Assertions: {}\n", active.assertions().len()));
    } else {
        output.push_str("  No active C2PA manifest found.\n");
    }

    if let Some(statuses) = reader.validation_status() {
        output.push_str(&format!("Validation Statuses ({}):\n", statuses.len()));
        for status in statuses {
            output.push_str(&format!("  - {}: {}\n", status.code(), status.explanation().unwrap_or("OK")));
        }
    }

    Ok(output)
}
