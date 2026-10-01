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

    let mut builder = Builder::from_json(&format!(
        r#"{{
            "claim_generator": "SignMedia/0.1.0",
            "title": "{}"
        }}"#,
        title
    ))?;

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
        _ => (
            include_bytes!("../../tests/fixtures/test_cert.pem").to_vec(),
            include_bytes!("../../tests/fixtures/test_key.pem").to_vec(),
        ),
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
    } else {
        output.push_str("  No active C2PA manifest found.\n");
    }
    Ok(output)
}
