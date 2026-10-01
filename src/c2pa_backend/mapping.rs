use anyhow::Result;
use c2pa::{Builder, Ingredient};
use serde_json::json;
use crate::models::{DerivativeWorkDescriptor, OriginalWorkDescriptor};

pub fn build_c2pa_manifest_for_owd(owd: &OriginalWorkDescriptor) -> Result<Builder> {
    let mut builder = Builder::from_json(&format!(
        r#"{{
            "claim_generator": "SignMedia/0.1.0",
            "title": "{}"
        }}"#,
        owd.title
    ))?;

    let author_name = owd
        .authors
        .first()
        .map(|a| a.name.as_str())
        .unwrap_or("Unknown Author");

    let actions = json!({
        "actions": [
            {
                "action": "c2pa.created",
                "parameters": {
                    "name": author_name,
                    "work_id": owd.work_id.to_string()
                }
            }
        ]
    });

    builder.add_assertion("c2pa.actions", &actions)?;

    Ok(builder)
}

pub fn build_c2pa_manifest_for_dwd(
    dwd: &DerivativeWorkDescriptor,
    parent_ingredient_json: Option<&str>,
) -> Result<Builder> {
    let mut builder = Builder::from_json(&format!(
        r#"{{
            "claim_generator": "SignMedia/0.1.0",
            "title": "{}"
        }}"#,
        dwd.original_owd.title
    ))?;

    if let Some(ing_json) = parent_ingredient_json {
        let ingredient = Ingredient::from_json(ing_json)?;
        builder.add_ingredient(ingredient);
    }

    let actions = json!({
        "actions": [
            {
                "action": "c2pa.edited",
                "parameters": {
                    "clipper_id": dwd.clipper_id,
                    "derivative_id": dwd.derivative_id.to_string()
                }
            }
        ]
    });

    builder.add_assertion("c2pa.actions", &actions)?;

    Ok(builder)
}
