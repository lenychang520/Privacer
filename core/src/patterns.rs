/// Built-in rules — regex patterns for all structured sensitive information
use fancy_regex::Regex;
use serde::{Deserialize, Serialize};

/// A detection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Unique identifier, e.g. "ipv4"
    pub name: String,
    /// Compiled regex pattern
    #[serde(skip)]
    pub compiled: Option<Regex>,
    /// Raw pattern string (for serialization/display)
    pub pattern: String,
    /// Replacement placeholder, e.g. "[IP]"
    pub placeholder: String,
    /// Priority — lower = matched first
    pub priority: i32,
}

impl Rule {
    pub fn new(name: &str, pattern: &str, placeholder: &str, priority: i32) -> Self {
        let compiled = Regex::new(pattern).ok();
        Self {
            name: name.to_string(),
            pattern: pattern.to_string(),
            compiled,
            placeholder: placeholder.to_string(),
            priority,
        }
    }
}

/// Built-in rules list (27 rules)
pub fn builtin_rules() -> Vec<Rule> {
    vec![
        // ── Network identity ──
        Rule::new(
            "ipv4",
            r"(?<![\.\d])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![\.\d])",
            "[IP]",
            0,
        ),
        // Hex IPv4
        Rule::new(
            "ipv4_hex",
            r"(?<![0-9a-fA-Fx])0x[0-9a-fA-F]{8}(?![0-9a-fA-F])",
            "[IP]",
            2,
        ),
        // IPv6
        Rule::new(
            "ipv6",
            r"\[?(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:)\]?",
            "[IP]",
            1,
        ),
        // IPv6 hyphen format
        Rule::new(
            "ipv6_hyphen",
            r"(?<![0-9a-fA-F-])[0-9a-fA-F]{4}(?:-[0-9a-fA-F]{4}){7}(?![0-9a-fA-F-])",
            "[IP]",
            2,
        ),
        // UUID (with hyphens)
        Rule::new(
            "uuid",
            r"(?<![a-fA-F\d-])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![a-fA-F\d-])",
            "[UUID]",
            0,
        ),
        // UUID without hyphens (32-char hex)
        Rule::new(
            "uuid_hex",
            r"(?<![a-fA-F\d])[0-9a-fA-F]{32}(?![a-fA-F\d])",
            "[UUID]",
            2,
        ),
        // Email
        Rule::new(
            "email",
            r"(?<![a-zA-Z0-9.%+-])[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}(?![a-zA-Z0-9.%+-])",
            "[EMAIL]",
            0,
        ),
        // Phone (China mainland)
        Rule::new(
            "phone_cn",
            r"(?<!\d)1[3-9]\d{9}(?!\d)",
            "[PHONE]",
            0,
        ),
        Rule::new(
            "phone_cn_sep",
            r"(?<!\d)\(?1[3-9]\d\)?[\s.\-]?\d{4}[\s.\-]?\d{4}(?!\d)",
            "[PHONE]",
            3,
        ),
        // Phone (international)
        Rule::new(
            "phone_intl",
            r"(?<!\d)\+[1-9]\d{0,2}[\s.\-]?(?:\d[\s.\-]?){5,14}\d(?!\d)",
            "[PHONE]",
            0,
        ),
        // ID Card (China mainland)
        Rule::new(
            "id_card_cn",
            r"(?<![Xx\d])[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[Xx\d](?![Xx\d])",
            "[ID_CARD]",
            0,
        ),
        Rule::new(
            "id_card_cn_sep",
            r"(?<![Xx\d])[1-9]\d{5}[\-\s]?(?:19|20)\d{2}[\-\s]?(?:0[1-9]|1[0-2])[\-\s]?(?:0[1-9]|[12]\d|3[01])[\-\s]?\d{3}[\-\s]?[Xx\d](?![Xx\d])",
            "[ID_CARD]",
            4,
        ),
        // US SSN
        Rule::new(
            "ssn_us",
            r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)",
            "[SSN]",
            0,
        ),
        // API Key (sk-/pk-/Bearer prefixes)
        Rule::new(
            "api_key_prefix",
            r"(?:(?i:sk|pk)-(?:[A-Za-z0-9]-?){14,}|(?i:Bearer)\s+[A-Za-z0-9_\-\.]{10,})",
            "[API_KEY]",
            0,
        ),
        // AWS Access Key
        Rule::new(
            "aws_access_key",
            r"(?<![A-Za-z0-9])(?i:AKIA)[0-9A-Za-z]{16}(?![A-Za-z0-9])",
            "[AWS_KEY]",
            0,
        ),
        // SSH private key
        Rule::new(
            "ssh_private_key",
            r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PRIVATE)\s+KEY-----[\s\S]*?-----END\s+(?:RSA|DSA|EC|OPENSSH|PRIVATE)\s+KEY-----",
            "[SSH_KEY]",
            0,
        ),
        // SSH public key
        Rule::new(
            "ssh_public_key",
            r"(?i)ssh-(?:rsa|ed25519|dss|ecdsa-sha2-nistp(?:256|384|521))\s+AAAA[A-Za-z0-9+/=]{20,}",
            "[SSH_KEY]",
            3,
        ),
        // SHA hash (64-char hex)
        Rule::new(
            "sha_hash",
            r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])",
            "[HASH]",
            6,
        ),
        // GitHub Token
        Rule::new(
            "github_token",
            r"(?<![a-zA-Z0-9_])(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{22,}(?![a-zA-Z0-9_])",
            "[GITHUB_TOKEN]",
            0,
        ),
        // JWT Token
        Rule::new(
            "jwt",
            r"(?<![a-zA-Z0-9_\-])eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?![a-zA-Z0-9_\-])",
            "[JWT]",
            0,
        ),
        Rule::new(
            "jwt_multiline",
            r"(?<![a-zA-Z0-9_\-])eyJ[A-Za-z0-9_-]{10,}\s*\.\s*\n?\s*[A-Za-z0-9_-]{4,}\s*\.\s*\n?\s*[A-Za-z0-9_-]{4,}(?![a-zA-Z0-9_\-])",
            "[JWT]",
            5,
        ),
        // Database connection strings
        Rule::new(
            "db_connection_string",
            r"(?:mysql|postgres|postgresql|mongodb|redis|sqlite|oracle|mssql)(?:\+[a-zA-Z]\w*)?://[^\s]+",
            "[DB_URL]",
            0,
        ),
        // CLI-form database connections
        Rule::new(
            "db_cli",
            r"(?:psql|mysql|mongo(?:sh)?|redis-cli|sqlite3|sqlcmd|pg_dump|pg_dumpall)\s+(?:-[a-zA-Z]+\s+\S+\s*)+",
            "[DB_CMD]",
            5,
        ),
        // Credential assignment (line-start)
        Rule::new(
            "credential_value",
            r"(?im)^\s*\w*(?:(?<=[_\\s])|(?<=^))(?i:password|secret|credential|token|api[_\\s]?keys?)(?=[_\\s:=]|[A-Z0-9])\w*\s*[:=]\s*\S{4,}",
            "[CREDENTIAL]",
            10,
        ),
        // URL query-string credentials
        Rule::new(
            "url_query_credential",
            r"(?i)[?&]\s*(?:user(?:name)?|pass(?:word)?|secret|token|key|auth)\s*=\s*[^&\s]{4,}",
            "[CREDENTIAL]",
            4,
        ),
        // Inline credential detection
        Rule::new(
            "credential_inline",
            r"(?i)(?<![a-zA-Z0-9])(?:[a-z_]+_)?(?:password|passwd|pwd|pass(?:word)?|secret|token|credential|auth(?:orization|entication|(?:[_\\s](?:token|key|code|secret)))|(?:(?:encrypt(?:ion)?|sign(?:ing)?|decrypt(?:ion)?|api|master|license|admin)[_\\s]?key))s?\s*[:=]\s*\S{4,}",
            "[CREDENTIAL]",
            5,
        ),
        // Credit card (format match; Luhn check used in detector)
        Rule::new(
            "credit_card",
            concat!(
                r"(?<![d\-])",
                r"(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))",
                r"[\-\s]?\d{4}[\-\s]?\d{4}[\-\s]?\d{4}",
                r"(?![d\-])",
            ),
            "[CARD]",
            0,
        ),
    ]
}
