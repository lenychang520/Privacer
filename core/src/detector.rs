use crate::config::{CustomRule, EntropyMode, PrivacerConfig};
use crate::entropy;
use crate::patterns;
use crate::preprocess;
use crate::whitelist;
use regex::Regex;
use once_cell::sync::Lazy;
use std::collections::HashSet;

const MAX_TEXT_LENGTH: usize = 100_000;
const IPV6_MAX_TEXT: usize = 5_000;

static REDOS_DANGER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\([^()]*(?:[+*]|\{\d+,?\d*\})[^()]*\)[+*]").unwrap()
});

#[derive(Debug, Clone)]
pub struct Match {
    pub rule_name: String,
    pub placeholder: String,
    pub start: usize,
    pub end: usize,
    pub value: String,
    pub entropy: f64,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Confidence {
    High,
    Low,
}

#[derive(Debug, Clone)]
pub struct FilterResult {
    pub text: String,
    pub matches: Vec<Match>,
    pub replacements: usize,
}

#[derive(Debug, Clone)]
pub struct DetectionConfig {
    pub entropy_threshold: f64,
    pub entropy_min_length: usize,
    pub enable_entropy: bool,
    pub entropy_mode: EntropyMode,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            entropy_threshold: 5.0,
            entropy_min_length: 12,
            enable_entropy: true,
            entropy_mode: EntropyMode::Auto,
        }
    }
}

impl From<&PrivacerConfig> for DetectionConfig {
    fn from(cfg: &PrivacerConfig) -> Self {
        Self {
            entropy_threshold: cfg.entropy.threshold,
            entropy_min_length: cfg.entropy.min_length,
            enable_entropy: cfg.entropy.enabled,
            entropy_mode: cfg.entropy.mode.clone(),
        }
    }
}



fn luhn_check(card_number: &str) -> bool {
    let digits: Vec<u32> = card_number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let mut sum = 0u32;
    let mut double = false;

    for &d in digits.iter().rev() {
        if double {
            let doubled = d * 2;
            sum += if doubled > 9 { doubled - 9 } else { doubled };
        } else {
            sum += d;
        }
        double = !double;
    }

    sum % 10 == 0
}

fn is_whitelisted(m: &Match, config: Option<&PrivacerConfig>) -> bool {
    let v = m.value.to_lowercase();

    if let Some(cfg) = config {
        if cfg.whitelist.strings.iter().any(|s| s.as_str() == v) {
            return true;
        }
    }

    match m.rule_name.as_str() {
        "ipv4" | "ipv4_hex" | "ipv6" | "ipv6_hyphen" => {
            if whitelist::is_whitelisted_ip(&v) {
                return true;
            }
            if let Some(cfg) = config {
                if cfg.whitelist.ips.iter().any(|ip| ip.to_lowercase() == v) {
                    return true;
                }
            }
            false
        }
        "email" => {
            if let Some(at_pos) = v.rfind('@') {
                let domain = &v[at_pos + 1..];
                if whitelist::is_whitelisted_domain(domain) {
                    return true;
                }
                if let Some(cfg) = config {
                    if cfg.whitelist.domains.iter().any(|d| d.to_lowercase() == domain) {
                        return true;
                    }
                }
            }
            false
        }
        _ => {
            whitelist::is_whitelisted_hostname(&v)
        }
    }
}

fn dedup_matches(mut matches: Vec<Match>) -> Vec<Match> {
    if matches.is_empty() {
        return matches;
    }

    matches.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| {
                let pa = patterns::builtin_rules()
                    .iter()
                    .find(|r| r.name == a.rule_name)
                    .map(|r| r.priority)
                    .unwrap_or(0);
                let pb = patterns::builtin_rules()
                    .iter()
                    .find(|r| r.name == b.rule_name)
                    .map(|r| r.priority)
                    .unwrap_or(0);
                pa.cmp(&pb)
            })
            .then_with(|| b.end.cmp(&a.end))
    });

    let mut deduped: Vec<Match> = Vec::new();
    for m in matches {
        match deduped.last() {
            None => deduped.push(m),
            Some(last) => {
                if m.start >= last.end {
                    // Non-overlapping
                    deduped.push(m);
                } else if m.start <= last.start && m.end >= last.end {
                    // m fully contains last → m wins
                    deduped.pop();
                    deduped.push(m);
                } else if last.start <= m.start && last.end >= m.end {
                    // last fully contains m → keep last
                    continue;
                } else {
                    // Partial overlap
                    let pa = patterns::builtin_rules()
                        .iter()
                        .find(|r| r.name == m.rule_name)
                        .map(|r| r.priority)
                        .unwrap_or(0);
                    let pb = patterns::builtin_rules()
                        .iter()
                        .find(|r| r.name == last.rule_name)
                        .map(|r| r.priority)
                        .unwrap_or(0);
                    if pa < pb || (pa == pb && (m.end - m.start) > (last.end - last.start)) {
                        deduped.pop();
                        deduped.push(m);
                    }
                }
            }
        }
    }

    deduped
}

fn apply_replacements(text: &str, matches: &[Match]) -> (String, usize) {
    if matches.is_empty() {
        return (text.to_string(), 0);
    }

    // Right-to-left replacement to avoid index drift
    let mut sorted = matches.to_vec();
    sorted.sort_by(|a, b| b.start.cmp(&a.start));

    let mut result = text.to_string();
    let mut count = 0;

    for m in &sorted {
        if m.confidence == Confidence::Low {
            continue;
        }
        result.replace_range(m.start..m.end, &m.placeholder);
        count += 1;
    }

    (result, count)
}

fn validate_regex_safety(pattern: &str, name: &str) -> Result<(), String> {
    if REDOS_DANGER.is_match(pattern) {
        return Err(format!(
            "Rule '{}': pattern contains nested quantifiers like (X+)+ which may cause ReDoS",
            name
        ));
    }
    // Compilation check
    Regex::new(pattern).map_err(|e| format!("Rule '{}': invalid regex: {}", name, e))?;
    Ok(())
}

fn run_rule(
    rule: &patterns::Rule,
    text: &str,
    config: Option<&PrivacerConfig>,
) -> Vec<Match> {
    let mut matches = Vec::new();

    // ReDoS guard: skip IPv6 regex on long text
    if (rule.name == "ipv6" || rule.name == "ipv6_hyphen") && text.len() > IPV6_MAX_TEXT {
        log::debug!("Skipping {} regex — text too long ({} chars)", rule.name, text.len());
        return matches;
    }

    if let Some(ref compiled) = rule.compiled {
        for cap_result in compiled.find_iter(text) {
            let cap = match cap_result {
                Ok(c) => c,
                Err(_) => continue,
            };
            let value = cap.as_str().to_string();
            let mut m = Match {
                rule_name: rule.name.clone(),
                placeholder: rule.placeholder.clone(),
                start: cap.start(),
                end: cap.end(),
                value,
                entropy: 0.0,
                confidence: Confidence::High,
            };

            // Apply placeholder override from config
            if let Some(cfg) = config {
                m.placeholder = cfg.get_placeholder(&rule.name, &m.placeholder);
            }

            if is_whitelisted(&m, config) {
                continue;
            }

            // Credit card Luhn check — low confidence on failure, still kept for scan
            if m.rule_name == "credit_card" {
                let stripped: String = m.value.chars().filter(|c| c.is_ascii_digit()).collect();
                if !luhn_check(&stripped) {
                    m.confidence = Confidence::Low;
                }
            }

            matches.push(m);
        }
    }
    matches
}

pub struct PrivacyDetector {
    config: PrivacerConfig,
    custom_compiled: Vec<(String, Regex, String, i32)>,
}

impl Default for PrivacyDetector {
    fn default() -> Self {
        Self::new(PrivacerConfig::default())
    }
}

impl PrivacyDetector {
    pub fn new(config: PrivacerConfig) -> Self {
        let mut custom_compiled: Vec<(String, Regex, String, i32)> = Vec::new();
        for cr in &config.custom_rules {
            if !cr.name.is_empty() && !cr.pattern.is_empty() {
                match Regex::new(&cr.pattern) {
                    Ok(re) => custom_compiled.push((cr.name.clone(), re, cr.placeholder.clone(), cr.priority)),
                    Err(e) => log::warn!("Skipping invalid custom rule '{}': {}", cr.name, e),
                }
            }
        }
        Self {
            config,
            custom_compiled,
        }
    }

    pub fn add_rule(&mut self, name: &str, pattern: &str, placeholder: &str, priority: i32) -> Result<(), String> {
        validate_regex_safety(pattern, name)?;
        let re = Regex::new(pattern).map_err(|e| format!("Invalid regex: {}", e))?;
        self.custom_compiled.push((
            name.to_string(),
            re,
            placeholder.to_string(),
            priority,
        ));
        Ok(())
    }

    pub fn add_rule_direct(&mut self, rule: CustomRule) -> Result<(), String> {
        self.add_rule(&rule.name, &rule.pattern, &rule.placeholder, rule.priority)
    }

    pub fn filter(&self, text: &str) -> FilterResult {
        self.filter_with(text, None, None)
    }

    pub fn filter_with(
        &self,
        text: &str,
        rules_filter: Option<&HashSet<String>>,
        placeholder_override: Option<&str>,
    ) -> FilterResult {
        if text.is_empty() {
            return FilterResult {
                text: String::new(),
                matches: Vec::new(),
                replacements: 0,
            };
        }

        // Rate canary (not a hard block)
        // Skipped for now to avoid &mut self conflict; can be added with interior mutability

        // Truncate excessively long text
        let truncated = if text.len() > MAX_TEXT_LENGTH {
            log::warn!("Input text too long ({} chars), truncating to {}", text.len(), MAX_TEXT_LENGTH);
            &text[..MAX_TEXT_LENGTH]
        } else {
            text
        };

        // Preprocess
        let normalized = self.preprocess(truncated);

        // Regex matches
        let regex_matches = self.find_regex_matches(&normalized, rules_filter, placeholder_override);

        // Entropy matches
        let mut entropy_matches: Vec<Match> = Vec::new();
        if self.config.entropy.enabled && self.config.entropy.mode == EntropyMode::Auto {
            let ent_matches = entropy::find_high_entropy(
                &normalized,
                self.config.entropy.threshold,
                self.config.entropy.min_length,
            );
            let covered: Vec<(usize, usize)> = regex_matches.iter().map(|m| (m.start, m.end)).collect();
            for em in ent_matches {
                let mut overlap = false;
                for &(s, e) in &covered {
                    if !(em.end <= s || em.start >= e) {
                        overlap = true;
                        break;
                    }
                }
                if !overlap {
                    entropy_matches.push(Match {
                        rule_name: "high_entropy".to_string(),
                        placeholder: "[SECRET]".to_string(),
                        start: em.start,
                        end: em.end,
                        value: em.value,
                        entropy: em.entropy,
                        confidence: Confidence::High,
                    });
                }
            }
        }

        let mut all_matches = regex_matches;
        all_matches.extend(entropy_matches);

        let deduped = dedup_matches(all_matches);
        let (filtered, count) = apply_replacements(&normalized, &deduped);

        FilterResult {
            text: filtered,
            matches: deduped,
            replacements: count,
        }
    }

    pub fn scan(&self, text: &str) -> Vec<Match> {
        self.scan_with(text, None)
    }

    pub fn scan_with(&self, text: &str, rules_filter: Option<&HashSet<String>>) -> Vec<Match> {
        if text.is_empty() {
            return Vec::new();
        }

        let truncated = if text.len() > MAX_TEXT_LENGTH {
            log::warn!("Input text too long ({} chars), truncating to {}", text.len(), MAX_TEXT_LENGTH);
            &text[..MAX_TEXT_LENGTH]
        } else {
            text
        };

        let normalized = self.preprocess(truncated);
        let mut regex_matches = self.find_regex_matches(&normalized, rules_filter, None);

        if self.config.entropy.enabled {
            let ent_matches = entropy::find_high_entropy(
                &normalized,
                self.config.entropy.threshold,
                self.config.entropy.min_length,
            );
            let covered: Vec<(usize, usize)> = regex_matches.iter().map(|m| (m.start, m.end)).collect();
            for em in ent_matches {
                let mut overlap = false;
                for &(s, e) in &covered {
                    if !(em.end <= s || em.start >= e) {
                        overlap = true;
                        break;
                    }
                }
                if !overlap {
                    regex_matches.push(Match {
                        rule_name: "high_entropy".to_string(),
                        placeholder: "[SECRET]".to_string(),
                        start: em.start,
                        end: em.end,
                        value: em.value,
                        entropy: em.entropy,
                        confidence: Confidence::High,
                    });
                }
            }
        }

        dedup_matches(regex_matches)
    }

    fn preprocess(&self, text: &str) -> String {
        let s = preprocess::normalize_text(text);
        // Config-driven preprocessing toggles are applied in normalize_text
        // Additional filtering can be added here if needed
        s
    }

    fn find_regex_matches(
        &self,
        text: &str,
        rules_filter: Option<&HashSet<String>>,
        placeholder_override: Option<&str>,
    ) -> Vec<Match> {
        let mut matches = Vec::new();

        // Built-in rules
        for rule in patterns::builtin_rules() {
            if let Some(filter) = rules_filter {
                if !filter.contains(&rule.name) {
                    continue;
                }
            }
            if !self.config.is_rule_enabled(&rule.name) {
                continue;
            }
            matches.extend(run_rule(&rule, text, Some(&self.config)));
        }

        // Apply placeholder override
        if let Some(ph) = placeholder_override {
            for m in &mut matches {
                m.placeholder = ph.to_string();
            }
        }

        // Custom rules
        for (name, re, placeholder, _priority) in &self.custom_compiled {
            if let Some(filter) = rules_filter {
                if !filter.contains(name) {
                    continue;
                }
            }
            for cap in re.find_iter(text) {
                let value = cap.as_str().to_string();
                let m = Match {
                    rule_name: name.clone(),
                    placeholder: placeholder.clone(),
                    start: cap.start(),
                    end: cap.end(),
                    value,
                    entropy: 0.0,
                    confidence: Confidence::High,
                };
                if !is_whitelisted(&m, Some(&self.config)) {
                    matches.push(m);
                }
            }
        }

        matches
    }

    pub fn config(&self) -> &PrivacerConfig {
        &self.config
    }
}

pub fn filter_text(text: &str, config: Option<&DetectionConfig>) -> FilterResult {
    match config {
        Some(cfg) => {
            let mut privacer_cfg = PrivacerConfig::default();
            privacer_cfg.entropy.enabled = cfg.enable_entropy;
            privacer_cfg.entropy.threshold = cfg.entropy_threshold;
            privacer_cfg.entropy.min_length = cfg.entropy_min_length;
            privacer_cfg.entropy.mode = cfg.entropy_mode.clone();
            let detector = PrivacyDetector::new(privacer_cfg);
            detector.filter(text)
        }
        None => {
            let detector = PrivacyDetector::default();
            detector.filter(text)
        }
    }
}

pub fn scan_text(text: &str, config: Option<&DetectionConfig>) -> Vec<Match> {
    match config {
        Some(cfg) => {
            let mut privacer_cfg = PrivacerConfig::default();
            privacer_cfg.entropy.enabled = cfg.enable_entropy;
            privacer_cfg.entropy.threshold = cfg.entropy_threshold;
            privacer_cfg.entropy.min_length = cfg.entropy_min_length;
            privacer_cfg.entropy.mode = cfg.entropy_mode.clone();
            let detector = PrivacyDetector::new(privacer_cfg);
            detector.scan(text)
        }
        None => {
            let detector = PrivacyDetector::default();
            detector.scan(text)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CustomRule, PrivacerConfig};

    fn detector() -> PrivacyDetector {
        PrivacyDetector::default()
    }

    // ── Basic detection tests ──

    #[test]
    fn test_ipv4_detection() {
        let d = detector();
        let result = d.filter("My IP is 192.168.1.1");
        assert!(result.replacements > 0);
        assert!(result.text.contains("[IP]"));
    }

    #[test]
    fn test_ipv4_public() {
        let d = detector();
        let result = d.filter("ssh root@203.0.113.1 ufw status");
        assert!(result.text.contains("[IP]"));
        assert!(!result.text.contains("203.0.113.1"));
    }

    #[test]
    fn test_email_detection() {
        let d = detector();
        let result = d.filter("Contact me at test@mycompany.com");
        assert!(result.replacements > 0);
        assert!(result.text.contains("[EMAIL]"));
    }

    #[test]
    fn test_whitelist_skips_localhost() {
        let d = detector();
        let result = d.filter("Server: 0.0.0.0");
        assert_eq!(result.replacements, 0);
    }

    #[test]
    fn test_credit_card_luhn() {
        let d = detector();
        let result = d.filter("Card: 4111 1111 1111 1111");
        assert!(result.replacements > 0);
        assert!(result.text.contains("[CARD]"));
    }

    #[test]
    fn test_invalid_card_skipped_in_filter() {
        let d = detector();
        let result = d.filter("Card: 1234 5678 9012 3456");
        assert_eq!(result.replacements, 0);
    }

    #[test]
    fn test_invalid_card_still_in_scan() {
        let d = detector();
        // 4392 has valid Visa prefix but fails Luhn
        let matches = d.scan("Card: 4392 5799 1234 5678");
        assert!(matches.iter().any(|m| m.rule_name == "credit_card"));
    }

    #[test]
    fn test_phone_detection() {
        let d = detector();
        let result = d.filter("Call me at 13800138000");
        assert!(result.replacements > 0);
        assert!(result.text.contains("[PHONE]"));
    }

    #[test]
    fn test_entropy_detection() {
        let d = detector();
        let key = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
        let result = d.filter(&format!("secret={}", key));
        assert!(result.replacements > 0);
    }

    #[test]
    fn test_normal_text_no_false_positives() {
        let d = detector();
        let result = d.filter("Hello, how are you? Today is a nice day.");
        assert_eq!(result.replacements, 0);
    }

    #[test]
    fn test_scan_does_not_modify() {
        let d = detector();
        let text = "My IP is 192.168.1.1";
        let matches = d.scan(text);
        assert!(!matches.is_empty());
        assert!(text.contains("192.168.1.1"));
    }

    // ── UUID ──

    #[test]
    fn test_uuid_with_hyphens() {
        let d = detector();
        let result = d.filter("UUID: 4e0a1c0d-3342-4d5b-8785-6618aff9b102");
        assert!(result.text.contains("[UUID]"));
        assert!(!result.text.contains("4e0a1c0d"));
    }

    #[test]
    fn test_uuid_no_hyphens() {
        let d = detector();
        let result = d.filter("trace id: 550e8400e29b41d4a716446655440000");
        assert!(result.text.contains("[UUID]"));
    }

    // ── API Key ──

    #[test]
    fn test_api_key() {
        let d = detector();
        let result = d.filter("Authorization: Bearer sk-abc123def45678901234567890");
        assert!(result.text.contains("[API_KEY]"));
        assert!(!result.text.contains("sk-abc123"));
    }

    #[test]
    fn test_github_token() {
        let d = detector();
        let result = d.filter("token is github_pat_11A22B33C44D55E66F77G88H99I00J11K22L33");
        assert!(result.text.contains("[GITHUB_TOKEN]"));
    }

    #[test]
    fn test_aws_key() {
        let d = detector();
        let result = d.filter("register AKIAQT4V25ABCD6EFGHJ test");
        assert!(result.text.contains("[AWS_KEY]"));
    }

    // ── SSH ──

    #[test]
    fn test_ssh_private_key() {
        let d = detector();
        let result = d.filter(
            "-----BEGIN PRIVATE KEY-----\nMIIEvg...\n-----END PRIVATE KEY-----"
        );
        assert!(result.text.contains("[SSH_KEY]"));
        assert!(!result.text.contains("MIIEvg"));
        assert!(!result.text.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_ssh_public_key() {
        let d = detector();
        let result = d.filter("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... user@host");
        assert!(result.text.contains("[SSH_KEY]"));
    }

    // ── IPv6 ──

    #[test]
    fn test_ipv6_brackets() {
        let d = detector();
        let result = d.filter("endpoint [2001:db8::1] port 443 timeout");
        assert!(result.text.contains("[IP]"));
        assert!(!result.text.contains("1]"));
    }

    #[test]
    fn test_ipv6_hyphen_format() {
        let d = detector();
        let result = d.filter("connect FE80-0000-0000-0000-0202-B3FF-FE1E-8329 failed");
        assert!(result.text.contains("[IP]"));
    }

    #[test]
    fn test_ipv4_hex() {
        let d = detector();
        let result = d.filter("address 0xC0A80101 maps to");
        assert!(result.text.contains("[IP]"));
    }

    // ── JWT ──

    #[test]
    fn test_jwt_multiline() {
        let d = detector();
        let result = d.filter(
            "token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\n\
             .\n\
             eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ\n\
             .\n\
             signature"
        );
        assert!(result.text.contains("[JWT]"));
    }

    // ── DB ──

    #[test]
    fn test_db_connection_string() {
        let d = detector();
        let result = d.filter("connect postgresql+psycopg2://admin:pass@db.example.com:5432/prod");
        assert!(result.text.contains("[DB_URL]"));
    }

    #[test]
    fn test_db_cli() {
        let d = detector();
        let result = d.filter("psql -h pg-server.internal -U readonly -d prod -p 5432");
        assert!(result.text.contains("[DB_CMD]"));
    }

    // ── Phone variants ──

    #[test]
    fn test_phone_parentheses() {
        let d = detector();
        let result = d.filter("phone (138) 1234-5678");
        assert!(result.text.contains("[PHONE]"));
    }

    #[test]
    fn test_phone_international() {
        let d = detector();
        let result = d.filter("phone +1-555-1234567");
        assert!(result.text.contains("[PHONE]"));
    }

    // ── ID Card ──

    #[test]
    fn test_id_card_cn() {
        let d = detector();
        let result = d.filter("ID: 110101199001011234");
        assert!(result.text.contains("[ID_CARD]"));
    }

    #[test]
    fn test_id_card_hyphens() {
        let d = detector();
        let result = d.filter("ID 110101-19900101-1234 verify");
        assert!(result.text.contains("[ID_CARD]"));
    }

    // ── SSN ──

    #[test]
    fn test_ssn_us() {
        let d = detector();
        let result = d.filter("SSN: 123-45-6789");
        assert!(result.text.contains("[SSN]"));
    }

    // ── Config-driven features ──

    #[test]
    fn test_custom_rule() {
        let mut cfg = PrivacerConfig::default();
        cfg.custom_rules.push(CustomRule {
            name: "test_project".to_string(),
            pattern: r"PROJ-\d{6}".to_string(),
            placeholder: "[PROJECT]".to_string(),
            priority: 50,
        });
        let d = PrivacyDetector::new(cfg);
        let result = d.filter("deploy PROJ-123456 to server");
        assert!(result.text.contains("[PROJECT]"));
    }

    #[test]
    fn test_disabled_rule() {
        let mut cfg = PrivacerConfig::default();
        cfg.rules.insert("ipv4".to_string(), false);
        let d = PrivacyDetector::new(cfg);
        let result = d.filter("My IP is 192.168.1.1");
        assert_eq!(result.replacements, 0);
    }

    #[test]
    fn test_placeholder_override() {
        let mut cfg = PrivacerConfig::default();
        cfg.placeholders.insert("ipv4".to_string(), "[HIDDEN_IP]".to_string());
        let d = PrivacyDetector::new(cfg);
        let result = d.filter("IP: 192.168.1.1");
        assert!(result.text.contains("[HIDDEN_IP]"));
    }

    #[test]
    fn test_whitelist_extra_domain() {
        let mut cfg = PrivacerConfig::default();
        cfg.whitelist.domains.push("mycompany.com".to_string());
        let d = PrivacyDetector::new(cfg);
        let result = d.filter("email admin@mycompany.com");
        assert_eq!(result.replacements, 0);
    }

    #[test]
    fn test_whitelist_extra_ip() {
        let mut cfg = PrivacerConfig::default();
        cfg.whitelist.ips.push("10.0.0.1".to_string());
        let d = PrivacyDetector::new(cfg);
        let result = d.filter("server 10.0.0.1");
        assert_eq!(result.replacements, 0);
    }

    // ── Entropy review mode ──

    #[test]
    fn test_entropy_review_mode_skips_replacement() {
        let mut cfg = PrivacerConfig::default();
        cfg.entropy.mode = EntropyMode::Review;
        cfg.entropy.threshold = 3.0; // low threshold to trigger
        let d = PrivacyDetector::new(cfg);
        let key = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
        let result = d.filter(&format!("secret={}", key));
        // In review mode, high-entropy is not replaced — only regex matches should work
        // The regex match for credential_value should still fire
        assert!(!result.text.contains("[SECRET]"));
    }

    // ── Rules loaded check ──

    #[test]
    fn test_rules_loaded() {
        let rules = patterns::builtin_rules();
        assert!(rules.len() >= 18);
    }

    // ── Luhn unit ──

    #[test]
    fn test_luhn_valid_visa() {
        assert!(luhn_check("4111111111111111"));
    }

    #[test]
    fn test_luhn_valid_mastercard() {
        assert!(luhn_check("5500000000000004"));
    }

    #[test]
    fn test_luhn_invalid() {
        assert!(!luhn_check("4392579912345678"));
    }

    #[test]
    fn test_luhn_too_short() {
        assert!(!luhn_check("1234"));
    }

    // ── Whitelist unit ──

    #[test]
    fn test_whitelisted_ip_zeros() {
        assert!(whitelist::is_whitelisted_ip("0.0.0.0"));
    }

    #[test]
    fn test_whitelisted_domain_localhost() {
        assert!(whitelist::is_whitelisted_domain("localhost"));
    }

    // ── Normalization ──

    #[test]
    fn test_normalization_fullwidth() {
        let d = detector();
        // Fullwidth digits for 13800138000 should be normalized by NFKC
        let result = d.filter("电话: \u{ff11}\u{ff13}\u{ff18}\u{ff10}\u{ff10}\u{ff11}\u{ff13}\u{ff18}\u{ff10}\u{ff10}\u{ff10}");
        assert!(result.text.contains("[PHONE]"));
    }

    #[test]
    fn test_fullwidth_credit_card_no_replace() {
        let d = detector();
        // Fullwidth digits — NFKC normalizes, card has Visa prefix 4392 but fails Luhn
        let result = d.filter("卡号 4392 5799 1234 5678");
        assert!(!result.text.contains("[CARD]"));
    }

    #[test]
    fn test_fullwidth_credit_card_scan() {
        let d = detector();
        // Invalid Luhn card with valid Visa prefix — scan should still find it
        let m = d.scan("卡号 4392 5799 1234 5678");
        assert!(m.iter().any(|x| x.rule_name == "credit_card"));
    }
}
