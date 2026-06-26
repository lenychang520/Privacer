use privacer_core::patterns;

fn main() {
    let rules = patterns::builtin_rules();
    let email_rule = rules.iter().find(|r| r.name == "email").unwrap();
    let re = email_rule.compiled.as_ref().unwrap();
    
    let text = "Contact me at test@example.com";
    println!("Testing: {:?}", text);
    
    for cap_result in re.find_iter(text) {
        match cap_result {
            Ok(cap) => println!("  Match: {:?} at {}..{}", cap.as_str(), cap.start(), cap.end()),
            Err(e) => println!("  Error: {:?}", e),
        }
    }
    
    // Also test without \w
    let simple = fancy_regex::Regex::new(r"[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}").unwrap();
    println!("\nWithout lookaround:");
    for cap_result in simple.find_iter(text) {
        match cap_result {
            Ok(cap) => println!("  Match: {:?} at {}..{}", cap.as_str(), cap.start(), cap.end()),
            Err(e) => println!("  Error: {:?}", e),
        }
    }
}
