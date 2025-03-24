use crate::detectors::detector_trait::InputDetector;
use std::collections::HashSet;
use regex::Regex;
use once_cell::sync::Lazy;

// Static regex patterns for better performance
static SUSPICIOUS_PATTERN_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"[^\\]\*|\([^)]*[^\\][|&][^)]*\)|[^\\][|]"#).unwrap()
});

static FILTER_BYPASS_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\)[^)]*\(|\([^(]*$|^[^(]*\)|%[0-9a-fA-F]{2}"#).unwrap()
});

/// Detector for LDAP Injection attacks
///
/// Detects attempts to manipulate LDAP queries through user input.
/// Focuses on LDAP special characters, operators, and filter manipulation.
pub struct LdapInjectionDetector {
    special_characters: HashSet<char>,
    suspicious_sequences: Vec<&'static str>,
}

impl LdapInjectionDetector {
    /// Create a new instance of the LDAP injection detector
    pub fn new() -> Self {
        // LDAP special characters to look for
        let mut special_characters = HashSet::new();
        for c in ['&', '|', '!', '=', '<', '>', '~', '*', '(', ')', '\\'] {
            special_characters.insert(c);
        }

        // LDAP special sequences and operators
        let suspicious_sequences = vec![
            ")(", ")(|", ")(&", "*)(", "*)(|", "*))((*)","*))(|(*))",
            "*))(|(objectclass=*", "*))(&(objectclass=*",
            ")(cn=", ")(uid=", ")(ou=", ")(o=", ")(dc=",
            "&(&", "|(&", "!(&", "|(|", "&(|", "!(!",
            "*)(&", "*)(|", ")(objectClass=*", ")(|(objectClass=*",
            "cn=*", "uid=*", "(&(", "|(|", "\\*))", "\\*)(", 
            ")(password=*", ")(mail=*", ")(cn=*", ")(sn=*"
        ];

        LdapInjectionDetector {
            special_characters,
            suspicious_sequences,
        }
    }

    /// Checks if the number of special characters exceeds a threshold
    fn has_suspicious_character_count(&self, input: &str) -> bool {
        let special_char_count = input.chars()
            .filter(|c| self.special_characters.contains(c))
            .count();
        
        // If the input contains more than 3 special LDAP characters, it's suspicious
        special_char_count > 3
    }

    /// Checks for suspicious LDAP operator sequences
    fn contains_suspicious_sequences(&self, input: &str) -> bool {
        for sequence in &self.suspicious_sequences {
            if input.contains(sequence) {
                return true;
            }
        }
        false
    }

    /// Checks for unbalanced parentheses, which might indicate injection attempts
    fn has_unbalanced_parentheses(&self, input: &str) -> bool {
        let mut open_count = 0;
        
        for c in input.chars() {
            match c {
                '(' => open_count += 1,
                ')' => {
                    if open_count > 0 {
                        open_count -= 1;
                    } else {
                        // More closing than opening parentheses
                        return true;
                    }
                },
                _ => {}
            }
        }
        
        // If we have more opening than closing parentheses
        open_count > 0
    }

    /// Checks for patterns that could be used to bypass LDAP filters
    fn contains_filter_bypass_patterns(&self, input: &str) -> bool {
        FILTER_BYPASS_REGEX.is_match(input)
    }

    /// Checks for wildcard usage patterns commonly seen in LDAP injections
    fn contains_suspicious_wildcards(&self, input: &str) -> bool {
        // Check for asterisks not preceded by backslash (unescaped wildcards)
        SUSPICIOUS_PATTERN_REGEX.is_match(input)
    }

    /// Checks for common LDAP attribute manipulation patterns
    fn contains_attribute_manipulation(&self, input: &str) -> bool {
        let input_lower = input.to_lowercase();
        
        // Common LDAP attributes that might be targeted
        let target_attributes = [
            "cn=", "uid=", "mail=", "sn=", "objectclass=", 
            "ou=", "o=", "dc=", "givenname=", "password="
        ];
        
        // Check for attribute pattern followed by wildcard or special character
        for attr in &target_attributes {
            if input_lower.contains(attr) && 
               (input_lower.contains(&format!("{}*", attr)) ||
                input_lower.contains(&format!("{}(", attr)) ||
                input_lower.contains(&format!("{})", attr)) ||
                input_lower.contains(&format!("{}|", attr)) ||
                input_lower.contains(&format!("{}&", attr))) {
                return true;
            }
        }
        
        false
    }

    /// Checks for URL encoding or hex encoding attempts
    fn contains_encoding(&self, input: &str) -> bool {
        // Check for URL encoding patterns like %3D (=), %28 ((), %29 ())
        input.contains("%3D") || input.contains("%28") || input.contains("%29") ||
        input.contains("%26") || input.contains("%7C") || input.contains("%21") ||
        // Check for common hex encoding patterns
        input.contains("\\x") || input.contains("0x") || 
        // Check for Unicode encoding
        input.contains("\\u")
    }

    /// Checks for common LDAP DN patterns that might be used for injection
    fn contains_dn_pattern(&self, input: &str) -> bool {
        // Check for DN patterns like cn=admin,dc=example,dc=com
        let parts: Vec<&str> = input.split(',').collect();
        
        // If we have multiple parts separated by commas, check if they match DN format
        if parts.len() >= 2 {
            let dn_attributes = ["cn=", "ou=", "dc=", "o=", "uid=", "l=", "st=", "c=", "street="];
            let mut matches_count = 0;
            let parts_len = parts.len(); // Store length before moving parts
            
            // Use &parts to avoid moving the vector
            for part in &parts {
                let part_lower = part.trim().to_lowercase();
                for attr in &dn_attributes {
                    if part_lower.starts_with(attr) {
                        matches_count += 1;
                        break;
                    }
                }
            }
            
            // If most parts match DN format, it's likely a DN
            return matches_count >= parts_len * 2 / 3;
        }
        
        false
    }
}

impl InputDetector for LdapInjectionDetector {
    fn detect(&self, input: &str) -> bool {
        if input.trim().is_empty() {
            return false;
        }
        
        // Check for unbalanced parentheses
        if self.has_unbalanced_parentheses(input) {
            return true;
        }
        
        // Check for suspicious sequences
        if self.contains_suspicious_sequences(input) {
            return true;
        }
        
        // Check for filter bypass patterns
        if self.contains_filter_bypass_patterns(input) {
            return true;
        }
        
        // Check for suspicious character count
        if self.has_suspicious_character_count(input) {
            return true;
        }
        
        // Check for suspicious wildcards
        if self.contains_suspicious_wildcards(input) {
            return true;
        }
        
        // Check for attribute manipulation
        if self.contains_attribute_manipulation(input) {
            return true;
        }
        
        // Check for encoding attempts
        if self.contains_encoding(input) {
            return true;
        }
        
        // Check for DN patterns (new check)
        if self.contains_dn_pattern(input) {
            return true;
        }
        
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_inputs() {
        let detector = LdapInjectionDetector::new();
        
        // Safe inputs should not be flagged
        assert!(!detector.detect("John Smith"), "Regular name should not be flagged");
        assert!(!detector.detect("user@example.com"), "Email should not be flagged");
        assert!(!detector.detect("Software Engineer"), "Job title should not be flagged");
        assert!(!detector.detect("Engineering Department"), "Department name should not be flagged");
        assert!(!detector.detect("cn=John Smith"), "Valid LDAP query should not be flagged");
        assert!(!detector.detect("uid=jsmith"), "Valid uid reference should not be flagged");
    }

    #[test]
    fn test_basic_ldap_injection() {
        let detector = LdapInjectionDetector::new();
        
        // Test basic LDAP injection patterns
        assert!(detector.detect(")(|(password=*))"), "Basic LDAP injection pattern should be detected");
        assert!(detector.detect("*)(uid=*)"), "Asterisk injection pattern should be detected");
        assert!(detector.detect(")(cn=admin"), "Attribute injection should be detected");
        assert!(detector.detect("))(&(objectClass=*"), "Object class injection should be detected");
        assert!(detector.detect("*)(|(objectClass=*)"), "Combined pattern should be detected");
    }

    #[test]
    fn test_advanced_ldap_injection() {
        let detector = LdapInjectionDetector::new();
        
        // Test more complex LDAP injection patterns
        assert!(detector.detect("user)(|(uid=*)(userPassword=*))"), "Complex injection should be detected");
        assert!(detector.detect("admin))(|(uid=*))"), "Advanced injection with multiple parentheses should be detected");
        assert!(detector.detect("*))%00"), "Null byte injection should be detected");
        assert!(detector.detect("*))\\00"), "Escaped null byte injection should be detected");
        assert!(detector.detect(")(uid=admin)(|(objectClass=*"), "Attribute with object class injection should be detected");
    }

    #[test]
    fn test_filter_bypass() {
        let detector = LdapInjectionDetector::new();
        
        // Test filter bypass techniques
        assert!(detector.detect("admin)(|(objectClass=*)(objectClass=*"), "Unclosed parentheses should be detected");
        assert!(detector.detect("admin)(&(objectClass=*"), "AND operation injection should be detected");
        assert!(detector.detect("admin)(|(!objectClass=*"), "NOT operation injection should be detected");
        assert!(detector.detect(")(uid=*)(sn=Smith"), "Multiple attribute query should be detected");
        assert!(detector.detect("jsmith)(cn=*)(sn=*"), "Double attribute wildcard should be detected");
    }

    #[test]
    fn test_encoded_injection() {
        let detector = LdapInjectionDetector::new();
        
        // Test encoded injections
        assert!(detector.detect("%29%28%7Cuid%3D%2A%29"), "URL encoded injection should be detected");
        assert!(detector.detect("\\29\\28\\7Cuid\\3D\\2A\\29"), "Hex escaped injection should be detected");
        assert!(detector.detect("admin\\u0029\\u0028\\u007C"), "Unicode encoded injection should be detected");
        assert!(detector.detect("\\x29\\x28\\x7C"), "Hex encoded injection should be detected");
        assert!(detector.detect("%29%28%7C%75%69%64%3D%2A%29"), "Full URL encoded injection should be detected");
    }
} 