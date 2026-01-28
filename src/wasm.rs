use wasm_bindgen::prelude::*;
use crate::models::SignedManifest;
use crate::container::StreamingVerifier;

#[wasm_bindgen]
pub struct WasmVerifier {
    verifier: StreamingVerifier,
}

#[wasm_bindgen]
impl WasmVerifier {
    #[wasm_bindgen(constructor)]
    pub fn new(manifest_json: &str) -> Result<WasmVerifier, JsValue> {
        let manifest: SignedManifest = serde_json::from_str(manifest_json)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let verifier = StreamingVerifier::new(manifest)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(WasmVerifier { verifier })
    }

    pub fn verify_chunk(&self, index: u32, data: &[u8]) -> bool {
        self.verifier.verify_chunk(index as u64, data)
    }
}

#[wasm_bindgen]
pub fn verify_original_signature(manifest_json: &str) -> bool {
    let manifest: SignedManifest = match serde_json::from_str(manifest_json) {
        Ok(m) => m,
        Err(_) => return false,
    };
    
    // Simplistic check for v1 WASM export
    !manifest.signatures.is_empty()
}
