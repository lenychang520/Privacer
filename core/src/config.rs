use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreprocessConfig {
    #[serde(default = "default_true")]
    pub strip_zw_chars: bool,
    #[serde(default = "default_true")]
    pub url_decode: bool,
    #[serde(default = "default_true")]
    pub html_unescape: bool,
}

impl Default for PreprocessConfig {
    fn default() -> Self {
        Self {
            strip_zw_chars: true,
            url_decode: true,
            html_unescape: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_entropy_threshold")]
    pub threshold: f64,
    #[serde(default = "default_entropy_min_length")]
    pub min_length: usize,
    #[serde(default = "default_entropy_mode")]
    pub mode: EntropyMode,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EntropyMode {
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "review")]
    Review,
}

impl Default for EntropyMode {
    fn default() -> Self {
        Self::Auto
    }
}

impl Default for EntropyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: 5.0,
            min_length: 12,
            mode: EntropyMode::Auto,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRule {
    pub name: String,
    pub pattern: String,
    #[serde(default = "default_placeholder")]
    pub placeholder: String,
    #[serde(default = "default_custom_priority")]
    pub priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistConfig {
    #[serde(default)]
    pub ips: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub strings: Vec<String>,
}

impl Default for WhitelistConfig {
    fn default() -> Self {
        Self {
            ips: Vec::new(),
            domains: Vec::new(),
            strings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacerConfig {
    #[serde(default)]
    pub preprocess: PreprocessConfig,
    #[serde(default)]
    pub entropy: EntropyConfig,
    #[serde(default = "default_rules_toggles")]
    pub rules: std::collections::HashMap<String, bool>,
    #[serde(default)]
    pub custom_rules: Vec<CustomRule>,
    #[serde(default)]
    pub placeholders: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub whitelist: WhitelistConfig,
}

impl Default for PrivacerConfig {
    fn default() -> Self {
        Self {
            preprocess: PreprocessConfig::default(),
            entropy: EntropyConfig::default(),
            rules: default_rules_toggles(),
            custom_rules: Vec::new(),
            placeholders: std::collections::HashMap::new(),
            whitelist: WhitelistConfig::default(),
        }
    }
}

fn default_true() -> bool { true }
fn default_entropy_threshold() -> f64 { 5.0 }
fn default_entropy_min_length() -> usize { 12 }
fn default_entropy_mode() -> EntropyMode { EntropyMode::Auto }
fn default_placeholder() -> String { "[REDACTED]".to_string() }
fn default_custom_priority() -> i32 { 50 }

fn default_rules_toggles() -> std::collections::HashMap<String, bool> {
    let names: Vec<&str> = vec![
        "ipv4", "ipv4_hex", "ipv6", "ipv6_hyphen",
        "uuid", "uuid_hex", "email",
        "phone_cn", "phone_cn_sep", "phone_intl",
        "id_card_cn", "id_card_cn_sep", "ssn_us",
        "api_key_prefix", "aws_access_key",
        "ssh_private_key", "ssh_public_key",
        "sha_hash", "github_token",
        "jwt", "jwt_multiline",
        "db_connection_string", "db_cli",
        "credit_card",
        "credential_value", "url_query_credential", "credential_inline",
    ];
    let mut m = std::collections::HashMap::new();
    for name in names {
        m.insert(name.to_string(), true);
    }
    m
}

impl PrivacerConfig {
    pub fn load_from_path(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config: {}", e))?;
        let config: PrivacerConfig = serde_yaml::from_str(&content)
            .map_err(|e| format!("Failed to parse config: {}", e))?;
        Ok(config)
    }

    pub fn is_rule_enabled(&self, name: &str) -> bool {
        self.rules.get(name).copied().unwrap_or(true)
    }

    pub fn get_placeholder(&self, name: &str, default_ph: &str) -> String {
        self.placeholders
            .get(name)
            .cloned()
            .unwrap_or_else(|| default_ph.to_string())
    }
}
