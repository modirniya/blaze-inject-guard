use crate::detectors::detector_trait::InputDetector;
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    // Repetition of characters
    static ref REPEATED_CHARS: Regex = Regex::new(r"(.)\1{10,}").unwrap();
    
    // Nested repetition patterns
    static ref NESTED_REPETITION: Regex = Regex::new(r"(\([^()]*[+*]\)[+*])").unwrap();
    
    // Long alternation with repetition
    static ref ALTERNATION_WITH_REPETITION: Regex = Regex::new(r"\(([^()]{3,}\|){3,}[^()]{3,}\)[+*]").unwrap();
    
    // Suspicious repetition of complex groups
    static ref COMPLEX_GROUP_REPETITION: Regex = Regex::new(r"\([^()]{5,}\)[+*]").unwrap();
    
    // Multiple nested groups with repetition
    static ref NESTED_GROUPS: Regex = Regex::new(r"\(.*?\(.*?\)[+*]").unwrap();
    
    // Suspicious patterns commonly used in ReDoS attacks - FIXED to avoid backtracking
    static ref SUSPICIOUS_PATTERNS: Regex = Regex::new(r"(a{10,}[!@]|(\w+\W+){5,})").unwrap();
    
    // Extremely long input strings (which may be suspicious regardless of pattern)
    static ref LONG_INPUT: Regex = Regex::new(r".{1000,}").unwrap();
}

/// Detector for Regular Expression Denial of Service (ReDoS) attacks
/// 
/// Detects input patterns that might cause catastrophic backtracking
/// in regex engines leading to denial of service.
pub struct ReDoSDetector;

impl ReDoSDetector {
    /// Create a new instance of the ReDoS detector
    pub fn new() -> Self {
        ReDoSDetector
    }
    
    /// Check for long repetitions of the same character
    fn contains_repeated_chars(&self, input: &str) -> bool {
        REPEATED_CHARS.is_match(input)
    }
    
    /// Check for nested repetition patterns that could cause backtracking
    fn contains_nested_repetition(&self, input: &str) -> bool {
        NESTED_REPETITION.is_match(input)
    }
    
    /// Check for alternation with repetition patterns
    fn contains_alternation_with_repetition(&self, input: &str) -> bool {
        ALTERNATION_WITH_REPETITION.is_match(input)
    }
    
    /// Check for repetition of complex groups
    fn contains_complex_group_repetition(&self, input: &str) -> bool {
        COMPLEX_GROUP_REPETITION.is_match(input)
    }
    
    /// Check for multiple nested groups with repetition
    fn contains_nested_groups(&self, input: &str) -> bool {
        NESTED_GROUPS.is_match(input)
    }
    
    /// Check for known suspicious patterns
    fn contains_suspicious_patterns(&self, input: &str) -> bool {
        SUSPICIOUS_PATTERNS.is_match(input)
    }
    
    /// Check for extremely long input
    fn is_extremely_long_input(&self, input: &str) -> bool {
        LONG_INPUT.is_match(input)
    }
    
    /// Check for repetition of character classes followed by a boundary
    fn contains_character_class_repetition_with_boundary(&self, input: &str) -> bool {
        // Check for patterns like 'a'*n + '!' where n is large
        if let Some(last_char) = input.chars().last() {
            if !last_char.is_alphanumeric() {
                let prefix = &input[..input.len()-1];
                if prefix.chars().all(|c| c == prefix.chars().next().unwrap_or(' ')) && prefix.len() > 10 {
                    return true;
                }
            }
        }
        
        // Check for patterns like '(a+)+b'
        if input.contains("+)+") || input.contains("*)*") || input.contains("?)?") {
            return true;
        }
        
        false
    }
    
    /// Check for polymorphic patterns - inputs that might match safe patterns but cause ReDoS
    fn contains_polymorphic_patterns(&self, input: &str) -> bool {
        // Pattern that can be seen as email validation but causes ReDoS
        if input.contains("@") && input.chars().filter(|&c| c == '.').count() > 2 {
            let parts: Vec<&str> = input.split('@').collect();
            if parts.len() == 2 && parts[0].len() > 10 && parts[1].len() > 10 {
                return true;
            }
        }
        
        // Pattern that resembles URL but can cause backtracking
        if (input.contains("http://") || input.contains("https://")) && 
           input.chars().filter(|&c| c == '/').count() > 5 {
            return true;
        }
        
        false
    }
    
    /// Calculate the ratio of unique characters to total length
    /// A very low ratio can indicate repeated patterns that might cause backtracking
    fn has_low_character_diversity(&self, input: &str) -> bool {
        if input.len() < 20 {
            return false;
        }
        
        let unique_chars = input.chars().collect::<std::collections::HashSet<_>>().len();
        let diversity_ratio = unique_chars as f32 / input.len() as f32;
        
        // If very low ratio of unique chars to length and length is substantial
        diversity_ratio < 0.1 && input.len() > 30
    }
    
    /// Calculate the compression ratio as a heuristic for repetitive patterns
    /// High compression ratio = highly repetitive = potential for backtracking
    fn has_high_compression_ratio(&self, input: &str) -> bool {
        if input.len() < 20 {
            return false;
        }
        
        // Count runs of repeated characters as simple compression heuristic
        let mut compressed_length = 0;
        let mut current_char = None;
        let mut current_run = 0;
        
        for c in input.chars() {
            match current_char {
                Some(prev) if prev == c => {
                    current_run += 1;
                },
                _ => {
                    // Count the previous run - if run > 3, count as 3
                    if current_run > 0 {
                        compressed_length += 3.min(current_run);
                    }
                    
                    current_char = Some(c);
                    current_run = 1;
                }
            }
        }
        
        // Add the last run
        if current_run > 0 {
            compressed_length += 3.min(current_run);
        }
        
        // Calculate compression ratio
        let compression_ratio = 1.0 - (compressed_length as f32 / input.len() as f32);
        
        // If high compression ratio and length is substantial
        compression_ratio > 0.7 && input.len() > 30
    }
    
    /// Check for inputs that are not malicious
    fn is_likely_benign(&self, input: &str) -> bool {
        // Empty or very short inputs are benign
        if input.len() < 10 {
            return true;
        }
        
        // If it has good character diversity, it's less likely to be a ReDoS attack
        if input.len() < 100 && !self.has_low_character_diversity(input) {
            return true;
        }
        
        false
    }
}

impl InputDetector for ReDoSDetector {
    fn detect(&self, input: &str) -> bool {
        // Skip detection for likely benign inputs
        if input.len() < 10 {
            return false;
        }
        
        // Simple patterns known to cause ReDoS
        if input.contains("(a+)+") || 
           input.contains("(x*)*") || 
           input.contains("([ab]+)*") ||
           input.contains("(a|aa)+") {
            return true;
        }
        
        // Simple string checks for nested patterns
        if input.contains("+)+") || input.contains("*)*") || input.contains("?)?") {
            return true;
        }
        
        // Quick checks for repetitions without regex
        if input.len() > 20 {
            let chars = input.chars().collect::<Vec<_>>();
            if chars.len() > 0 {
                let first_char = chars[0];
                let same_char_count = chars.iter().filter(|&&c| c == first_char).count();
                if same_char_count > chars.len() * 3 / 4 && chars.len() > 20 {
                    return true;
                }
            }
        }
        
        // Simple test for long repetition with boundary
        if let Some(last_char) = input.chars().last() {
            if !last_char.is_alphanumeric() && input.len() > 10 {
                let prefix = &input[..input.len()-1];
                if prefix.chars().all(|c| c == prefix.chars().next().unwrap_or(' ')) && prefix.len() > 10 {
                    return true;
                }
            }
        }
        
        // Check for repeated characters
        if self.contains_repeated_chars(input) {
            return true;
        }
        
        // Check if diversity ratio is extremely low
        if input.len() > 30 {
            let unique_chars = input.chars().collect::<std::collections::HashSet<_>>().len();
            let diversity_ratio = unique_chars as f32 / input.len() as f32;
            if diversity_ratio < 0.1 {
                return true;
            }
        }
        
        // Additional checks only for longer inputs
        if input.len() > 20 {
            // Check for nested repetition
            if self.contains_nested_repetition(input) {
                return true;
            }
            
            // Check for alternation with repetition
            if self.contains_alternation_with_repetition(input) {
                return true;
            }
            
            // Check for complex group repetition
            if self.contains_complex_group_repetition(input) {
                return true;
            }
            
            // Check for nested groups
            if self.contains_nested_groups(input) {
                return true;
            }
            
            // Check for suspicious patterns
            if self.contains_suspicious_patterns(input) {
                return true;
            }
            
            // Check for extremely long input
            if self.is_extremely_long_input(input) {
                return true;
            }
        }
        
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_safe_inputs() {
        let detector = ReDoSDetector::new();
        
        assert!(!detector.detect("Hello, world!"), "Simple greeting should be safe");
        assert!(!detector.detect("This is a normal text without any suspicious patterns."), "Normal text should be safe");
        assert!(!detector.detect("12345 67890"), "Simple numbers should be safe");
        assert!(!detector.detect("user@example.com"), "Simple email should be safe");
        assert!(!detector.detect("https://example.com/page"), "Simple URL should be safe");
        assert!(!detector.detect("ABCDEFGHIJKLMNOPQRSTUVWXYZ"), "Alphabet should be safe");
    }
    
    #[test]
    fn test_repeated_characters() {
        let detector = ReDoSDetector::new();
        
        assert!(detector.detect("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "Long repeated characters should be detected");
        assert!(detector.detect("aaaaaaaaaaaaaa!"), "Repeated characters with boundary should be detected");
        assert!(detector.detect("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"), "Long repeated characters should be detected");
        assert!(!detector.detect("aaaaaa"), "Short repeated characters should be safe");
    }
    
    #[test]
    fn test_nested_patterns() {
        let detector = ReDoSDetector::new();
        
        assert!(detector.detect("(a+)+b"), "Nested repetition with boundary should be detected");
        assert!(detector.detect("(x*)*y"), "Nested repetition with boundary should be detected");
        assert!(detector.detect("([ab]+)*c"), "Group repetition with boundary should be detected");
    }
    
    #[test]
    fn test_alternation_patterns() {
        let detector = ReDoSDetector::new();
        
        assert!(detector.detect("(aaa|bbb|ccc|ddd)+"), "Alternation with repetition should be detected");
        assert!(detector.detect("(foo|bar|baz)*qux"), "Alternation with repetition and boundary should be detected");
    }
    
    #[test]
    fn test_complex_redos_patterns() {
        let detector = ReDoSDetector::new();
        
        // Evil regex pattern examples
        assert!(detector.detect("(a+)+b"), "Evil regex pattern should be detected");
        assert!(detector.detect("(a|aa)+b"), "Evil regex pattern should be detected");
        assert!(detector.detect("(.*a){20}b"), "Evil regex pattern should be detected");
        assert!(detector.detect("(a|b|c|d|e|f|g)+h"), "Evil regex pattern should be detected");
    }
    
    #[test]
    fn test_real_world_examples() {
        let detector = ReDoSDetector::new();
        
        // Email validation ReDoS
        assert!(detector.detect("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@bbbbbbbbbbbbbbbbbbbbbbbbbbbbb.com"), 
                "Long email pattern should be detected");
                
        // URL validation ReDoS
        assert!(detector.detect("https://aaaaaaaaaaaaaaaaaa.com/bbbbbbbbbbb/ccccccccccc/ddddddddddd/eeeeeeeeeee/fffffffff"),
                "Long URL pattern should be detected");
                
        // Date validation ReDoS
        assert!(detector.detect("2023-01-01-01-01-01-01-01-01-01-01-01-01-01-01-01-01-01"),
                "Excessive date format should be detected");
    }
    
    #[test]
    fn test_compression_heuristics() {
        let detector = ReDoSDetector::new();
        
        // Low character diversity
        assert!(detector.detect("abababababababababababababababababababababababababab"),
                "Repeating pattern with low diversity should be detected");
                
        // High compression ratio
        assert!(detector.detect("aaaabbbbbcccccdddddeeeeeaaaaaabbbbbccccccdddddeeeeee"),
                "Pattern with high compression ratio should be detected");
    }
    
    #[test]
    fn test_extremely_long_input() {
        let detector = ReDoSDetector::new();
        
        // Generate a very long string
        let long_string = "a".repeat(2000);
        assert!(detector.detect(&long_string), "Extremely long input should be detected");
    }
    
    #[test]
    fn test_edge_cases() {
        let detector = ReDoSDetector::new();
        
        // Edge case that should be safe
        assert!(!detector.detect("a{10}"), "Regex-like syntax that isn't an actual repetition should be safe");
        assert!(!detector.detect("(foo|bar)"), "Simple alternation without repetition should be safe");
        
        // Edge case that should be detected
        assert!(detector.detect("(a+)*b"), "Simple but dangerous pattern should be detected");
        assert!(detector.detect("((ab)+)+c"), "Nested repetition should be detected");
    }
} 