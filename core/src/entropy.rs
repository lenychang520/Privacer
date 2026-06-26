use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

/// A match found by the high-entropy detector.
#[derive(Clone, Debug)]
pub(crate) struct EntropyMatch {
    pub(crate) value: String,
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) entropy: f64,
    pub(crate) length: usize,
}

const MAX_SAMPLE_LENGTH: usize = 1024;

/// Compute the Shannon entropy of the given string.
fn shannon_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let total = data.chars().count() as f64;
    let mut counter: HashMap<char, usize> = HashMap::new();
    for ch in data.chars() {
        *counter.entry(ch).or_insert(0) += 1;
    }
    let mut entropy = 0.0;
    for &count in counter.values() {
        let p = count as f64 / total;
        entropy -= p * p.log2();
    }
    entropy
}

static NON_SECRET_PATTERNS: Lazy<Vec<Regex>> =
    Lazy::new(|| vec![Regex::new(r"(?i)data:[^;]+;base64,").unwrap()]);

static CJK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[\u{4e00}-\u{9fff}\u{3040}-\u{309f}\u{30a0}-\u{30ff}\u{ac00}-\u{d7af}]").unwrap()
});

/// Heuristic to filter out strings that are unlikely to be secrets.
fn may_be_secret(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    // All characters the same (e.g. "aaaaaa...")
    let first = value.chars().next().unwrap();
    if value.chars().all(|c| c == first) {
        return false;
    }
    // Contains newlines, carriage returns, or tabs
    if value.chars().any(|c| c == '\n' || c == '\r' || c == '\t') {
        return false;
    }
    // Matches known non-secret patterns (e.g. base64 data URIs)
    for pat in NON_SECRET_PATTERNS.iter() {
        if pat.is_match(value) {
            return false;
        }
    }
    // CJK / Hangul characters exceed 30%
    let cjk_count = CJK_RE.find_iter(value).count();
    if (cjk_count as f64) > value.chars().count() as f64 * 0.3 {
        return false;
    }
    // Spaces (regular and ideographic) exceed 25%
    let spaces = value
        .chars()
        .filter(|&c| c == ' ' || c == '\u{3000}')
        .count();
    if (spaces as f64) > value.chars().count() as f64 * 0.25 {
        return false;
    }
    true
}

/// Find high-entropy strings in `text` that exceed the given entropy threshold.
pub(crate) fn find_high_entropy(
    text: &str,
    threshold: f64,
    min_length: usize,
) -> Vec<EntropyMatch> {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() < min_length {
        return Vec::new();
    }

    let sample_len = std::cmp::min(chars.len(), MAX_SAMPLE_LENGTH);
    let step = std::cmp::max(1, min_length / 3);
    let mut matches: Vec<EntropyMatch> = Vec::new();
    let mut pos = 0;

    while pos + min_length <= sample_len {
        let window: String = chars[pos..pos + min_length].iter().collect();
        let entropy = shannon_entropy(&window);

        if entropy >= threshold {
            let mut extended_end = pos + min_length;
            while extended_end < sample_len {
                let test_window: String = chars[pos..=extended_end].iter().collect();
                if shannon_entropy(&test_window) >= threshold {
                    extended_end += 1;
                } else {
                    break;
                }
            }
            let value: String = chars[pos..extended_end].iter().collect();
            if may_be_secret(&value) {
                let full_entropy = shannon_entropy(&value);
                matches.push(EntropyMatch {
                    value,
                    start: pos,
                    end: extended_end,
                    entropy: full_entropy,
                    length: extended_end - pos,
                });
            }
            pos = extended_end;
        } else {
            pos += step;
        }
    }

    // Deduplicate overlapping matches
    matches.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| b.length.cmp(&a.length)));
    let mut deduped: Vec<EntropyMatch> = Vec::new();
    for m in matches {
        if let Some(last) = deduped.last() {
            if m.start < last.end {
                if m.length > last.length {
                    let idx = deduped.len() - 1;
                    deduped[idx] = m;
                }
            } else {
                deduped.push(m);
            }
        } else {
            deduped.push(m);
        }
    }
    deduped
}
