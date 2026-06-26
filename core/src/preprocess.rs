use regex::Regex;
use once_cell::sync::Lazy;
use unicode_normalization::UnicodeNormalization;

static URL_ENCODED: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"%[0-9a-fA-F]{2}").unwrap()
});

/// Comprehensive zero-width / invisible character set
static ZERO_WIDTH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad\u2060\u2061\u2062\u2063\u2064\u2066\u2067\u2068\u2069\ufe00-\ufe0f]").unwrap()
});

static HTML_ENTITY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"&(?:amp|lt|gt|quot|#[xX]?[0-9a-fA-F]+);").unwrap()
});

/// Normalize text for detection: NFKC → URL decode (iterative) → HTML unescape → strip zero-width
pub fn normalize_text(text: &str) -> String {
    let s: String = text.nfkc().collect();
    let s = url_decode_iterative(&s);
    let s = html_unescape(&s);
    ZERO_WIDTH.replace_all(&s, "").to_string()
}

/// Iterative URL decode (max 3 passes) to catch double-encoded sequences
fn url_decode_iterative(s: &str) -> String {
    let mut result = s.to_string();
    for _ in 0..3 {
        let decoded = url_decode_once(&result);
        if decoded == result {
            break;
        }
        result = decoded;
    }
    result
}

fn url_decode_once(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else {
            result.push(c);
        }
    }

    result
}

fn html_unescape(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '&' {
            let entity: String = chars.by_ref().take_while(|&ch| ch != ';').collect();
            if !entity.is_empty() {
                let decoded = match entity.as_str() {
                    "amp" => Some("&"),
                    "lt" => Some("<"),
                    "gt" => Some(">"),
                    "quot" => Some("\""),
                    "apos" => Some("'"),
                    "nbsp" => Some(" "),
                    _ => None,
                };
                if let Some(s) = decoded {
                    result.push_str(s);
                    continue;
                }
                if entity.starts_with("#x") || entity.starts_with("#X") {
                    let hex = &entity[2..];
                    if let Ok(code) = u32::from_str_radix(hex, 16) {
                        if let Some(ch) = char::from_u32(code) {
                            result.push(ch);
                            continue;
                        }
                    }
                } else if entity.starts_with('#') {
                    let num = &entity[1..];
                    if let Ok(code) = num.parse::<u32>() {
                        if let Some(ch) = char::from_u32(code) {
                            result.push(ch);
                            continue;
                        }
                    }
                }
            }
            result.push('&');
            result.push_str(&entity);
            result.push(';');
        } else {
            result.push(c);
        }
    }

    result
}

pub fn is_already_normalized(text: &str) -> bool {
    !URL_ENCODED.is_match(text)
        && !ZERO_WIDTH.is_match(text)
        && !HTML_ENTITY.is_match(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_decode() {
        assert_eq!(url_decode_once("hello%20world"), "hello world");
        assert_eq!(url_decode_once("%48%65%6c%6c%6f"), "Hello");
    }

    #[test]
    fn test_url_decode_iterative() {
        // Double-encoded
        let result = url_decode_iterative("hello%2520world");
        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_html_unescape() {
        assert_eq!(html_unescape("a&lt;b&gt;c"), "a<b>c");
        assert_eq!(html_unescape("&amp;test"), "&test");
        assert_eq!(html_unescape("&#65;&#66;&#67;"), "ABC");
        assert_eq!(html_unescape("&#x41;&#x42;&#x43;"), "ABC");
        assert_eq!(html_unescape("&apos;test&apos;"), "'test'");
        assert_eq!(html_unescape("&nbsp;hello"), " hello");
    }

    #[test]
    fn test_normalize_text() {
        let result = normalize_text("hello%20&amp;world\u{200b}");
        assert_eq!(result, "hello &world");
    }

    #[test]
    fn test_normalize_double_encoded() {
        let result = normalize_text("hello%2520world&#65;");
        assert_eq!(result, "hello worldA");
    }

    #[test]
    fn test_normalize_zero_width_extended() {
        let result = normalize_text("test\u{200b}\u{200c}\u{200d}\u{200e}\u{200f}\u{2060}\u{2061}\u{2062}\u{2063}\u{2064}\u{2066}\u{2067}\u{2068}\u{2069}\u{feff}\u{00ad}\u{fe00}x");
        assert_eq!(result, "testx");
    }
}
