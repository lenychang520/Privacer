use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

static IP_WHITELIST_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"^0\.0\.0\.0$").unwrap(),
        Regex::new(r"^255\.255\.255\.255$").unwrap(),
    ]
});

static DOMAIN_WHITELIST: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        "localhost",
        "localhost.localdomain",
        "example.com",
        "example.org",
        "example.net",
        "test.com",
        "test.local",
    ])
});

static HOSTNAME_WHITELIST: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from(["localhost"])
});

pub(crate) fn is_whitelisted_ip(ip: &str) -> bool {
    IP_WHITELIST_PATTERNS.iter().any(|pattern| pattern.is_match(ip))
}

pub(crate) fn is_whitelisted_domain(domain: &str) -> bool {
    DOMAIN_WHITELIST.contains(domain)
}

pub(crate) fn is_whitelisted_hostname(hostname: &str) -> bool {
    HOSTNAME_WHITELIST.contains(hostname)
}
