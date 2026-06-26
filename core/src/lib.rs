pub mod patterns;
pub mod preprocess;
pub mod entropy;
pub mod whitelist;
pub mod detector;
pub mod config;

pub use config::{PrivacerConfig, CustomRule, EntropyMode, PreprocessConfig, EntropyConfig, WhitelistConfig};
pub use detector::{filter_text, scan_text, Match, FilterResult, DetectionConfig, Confidence, PrivacyDetector};
