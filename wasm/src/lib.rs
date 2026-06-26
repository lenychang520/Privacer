use wasm_bindgen::prelude::*;
use privacer_core::{filter_text, scan_text, DetectionConfig};

#[wasm_bindgen]
pub struct PrivacerResult {
    text: String,
    replacements: usize,
}

#[wasm_bindgen]
impl PrivacerResult {
    pub fn text(&self) -> String { self.text.clone() }
    pub fn replacements(&self) -> usize { self.replacements }
}

/// Filter sensitive data from text (with entropy detection enabled by default)
#[wasm_bindgen]
pub fn filter(text: &str, enable_entropy: bool) -> PrivacerResult {
    let config = DetectionConfig {
        enable_entropy,
        ..Default::default()
    };
    let result = filter_text(text, Some(&config));
    PrivacerResult {
        text: result.text,
        replacements: result.replacements,
    }
}

/// Check if text contains sensitive data (returns match count)
#[wasm_bindgen]
pub fn scan(text: &str, enable_entropy: bool) -> usize {
    let config = DetectionConfig {
        enable_entropy,
        ..Default::default()
    };
    scan_text(text, Some(&config)).len()
}
