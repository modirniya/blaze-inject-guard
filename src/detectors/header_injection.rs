use crate::detectors::detector_trait::InputDetector;
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    // Pattern to match CR/LF sequences in various forms
    static ref CRLF_PATTERN: Regex = Regex::new(r"(\r\n|%0[dD]%0[aA]|%0[aA]%0[dD]|\\r\\n|\\n|\\r|\r|\n)").unwrap();
    
    // Pattern to check for common header names that might be injected
    static ref HEADER_PATTERN: Regex = Regex::new(r"(?i)(Set-Cookie|Location|Content-Type|Content-Disposition|X-XSS-Protection|Content-Security-Policy|Access-Control|Authorization):").unwrap();
    
    // Pattern to detect URL encoded CR/LF with header names
    static ref ENCODED_HEADER_PATTERN: Regex = Regex::new(r"(?i)(%0[dD]|%0[aA]|\\r|\\n).*?(Set-Cookie|Location|Content-Type|Authorization):").unwrap();
    
    // Pattern to detect hex/unicode encoding attempts
    static ref HEX_UNICODE_PATTERN: Regex = Regex::new(r"(?i)(\\u000[aAdD]|\\x0[aAdD]|%u000[aAdD])").unwrap();
    
    // Pattern to detect obfuscated CR/LF with decimal and other encodings
    static ref OBFUSCATED_CRLF: Regex = Regex::new(r"(?i)(%0?[dD]%0?[aA]|\\?[rR]\\?[nN]|&#0?1[30];&#0?1[30];|&#[xX]0?[dD];&#[xX]0?[aA];)").unwrap();
}

/// Detector for HTTP Header Injection attacks
/// 
/// Detects attempts to inject newlines (CR/LF) to add unauthorized HTTP headers,
/// which could lead to response splitting, session hijacking, or XSS.
pub struct HeaderInjectionDetector;

impl HeaderInjectionDetector {
    /// Create a new instance of the header injection detector
    pub fn new() -> Self {
        HeaderInjectionDetector
    }
    
    /// Check for CR/LF characters that could split headers
    fn contains_crlf(&self, input: &str) -> bool {
        CRLF_PATTERN.is_match(input) || HEX_UNICODE_PATTERN.is_match(input) || OBFUSCATED_CRLF.is_match(input)
    }
    
    /// Check for header names following potential CR/LF
    fn contains_header_names(&self, input: &str) -> bool {
        HEADER_PATTERN.is_match(input) || ENCODED_HEADER_PATTERN.is_match(input)
    }
    
    /// Check if the input contains specific header injection patterns
    fn contains_specific_patterns(&self, input: &str) -> bool {
        let lower_input = input.to_lowercase();
        
        // Check for common cookie injection patterns
        lower_input.contains("set-cookie:") || 
        lower_input.contains("set-cookie=") ||
        
        // Check for location header injection
        lower_input.contains("location:") ||
        lower_input.contains("location=") ||
        
        // Check for XSS through content-type
        lower_input.contains("content-type:") && 
        lower_input.contains("html") ||
        
        // Check for potential CRLF + XSS combination
        (self.contains_crlf(input) && 
         (lower_input.contains("<script") || 
          lower_input.contains("javascript:")))
    }
    
    /// Check for session hijacking attempts
    fn contains_session_hijacking(&self, input: &str) -> bool {
        let lower_input = input.to_lowercase();
        
        self.contains_crlf(input) && 
        (lower_input.contains("session=") || 
         lower_input.contains("cookie=") || 
         lower_input.contains("authorization=") || 
         lower_input.contains("token=") ||
         lower_input.contains("sid="))
    }
    
    /// Check if the input contains URL encoded CRLF
    fn contains_url_encoded_crlf(&self, input: &str) -> bool {
        input.contains("%0d") || 
        input.contains("%0D") || 
        input.contains("%0a") || 
        input.contains("%0A")
    }
    
    /// Check if the input is likely benign for header context
    fn is_likely_benign(&self, input: &str) -> bool {
        // Very short inputs are unlikely to be header injection
        if input.len() < 4 {
            return true;
        }
        
        // No newlines, carriage returns, or their encoded forms
        !self.contains_crlf(input) &&
        !self.contains_url_encoded_crlf(input) &&
        !input.contains("\\r") &&
        !input.contains("\\n") &&
        
        // No header names in the input
        !self.contains_header_names(input)
    }
}

impl InputDetector for HeaderInjectionDetector {
    fn detect(&self, input: &str) -> bool {
        if input.trim().is_empty() {
            return false;
        }
        
        // Skip detection for obviously benign inputs
        if self.is_likely_benign(input) {
            return false;
        }
        
        // Look for CRLF with header names - primary header injection
        if self.contains_crlf(input) && self.contains_header_names(input) {
            return true;
        }
        
        // Check for URL encoded CRLF sequences
        if self.contains_url_encoded_crlf(input) {
            return true;
        }
        
        // Check for specific header injection patterns
        if self.contains_specific_patterns(input) {
            return true;
        }
        
        // Check for session hijacking attempts
        if self.contains_session_hijacking(input) {
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
        let detector = HeaderInjectionDetector::new();
        
        assert!(!detector.detect("John Smith"), "Simple name should be safe");
        assert!(!detector.detect("johndoe@example.com"), "Email address should be safe");
        assert!(!detector.detect("example.com/path/to/resource"), "URL path should be safe");
        assert!(!detector.detect("This is a normal comment."), "Normal text should be safe");
        assert!(!detector.detect("<p>Regular HTML content</p>"), "HTML should be safe");
    }
    
    #[test]
    fn test_basic_header_injection() {
        let detector = HeaderInjectionDetector::new();
        
        assert!(detector.detect("foo\r\nSet-Cookie: session=hijacked"), "CRLF header injection should be detected");
        assert!(detector.detect("foo\nSet-Cookie: session=hijacked"), "LF header injection should be detected");
        assert!(detector.detect("foo\rSet-Cookie: session=hijacked"), "CR header injection should be detected");
        assert!(detector.detect("foo%0d%0aSet-Cookie: session=hijacked"), "URL encoded CRLF should be detected");
    }
    
    #[test]
    fn test_complex_header_injection() {
        let detector = HeaderInjectionDetector::new();
        
        assert!(detector.detect("foo%0aContent-Type: text/html%0a%0a<script>alert(1)</script>"), 
               "XSS through Content-Type should be detected");
        assert!(detector.detect("foo%0d%0aLocation: https://evil.com%0d%0a"), 
               "Redirect through Location header should be detected");
        assert!(detector.detect("normal text%0D%0AContent-Length: 0%0D%0A%0D%0AHTTP/1.1 200 OK%0D%0AContent-Type: text/html%0D%0A%0D%0A<html>Fake response</html>"), 
               "HTTP response splitting should be detected");
    }
    
    #[test]
    fn test_session_hijacking() {
        let detector = HeaderInjectionDetector::new();
        
        assert!(detector.detect("test%0d%0aSet-Cookie: session=stolen_token"), 
               "Session hijacking with Set-Cookie should be detected");
        assert!(detector.detect("user%0d%0aSet-Cookie: JSESSIONID=hijacked_value"), 
               "JSESSIONID hijacking should be detected");
        assert!(detector.detect("foo%0d%0aSet-Cookie: auth=admin; path=/"), 
               "Auth cookie hijacking should be detected");
    }
    
    #[test]
    fn test_encoded_variants() {
        let detector = HeaderInjectionDetector::new();
        
        assert!(detector.detect("test%0D%0ASet-Cookie: session=hijacked"), 
               "Uppercase URL encoding should be detected");
        assert!(detector.detect("test\\r\\nSet-Cookie: session=hijacked"), 
               "Backslash encoded CRLF should be detected");
        assert!(detector.detect("test\\u000d\\u000aSet-Cookie: session=hijacked"), 
               "Unicode escaped CRLF should be detected");
        assert!(detector.detect("test&#13;&#10;Set-Cookie: session=hijacked"), 
               "HTML entity encoded CRLF should be detected");
    }
    
    #[test]
    fn test_obfuscation_techniques() {
        let detector = HeaderInjectionDetector::new();
        
        assert!(detector.detect("test%00%0d%0aSet-Cookie: session=hijacked"), 
               "Null byte with CRLF should be detected");
        assert!(detector.detect("test%0d\\nSet-Cookie: session=hijacked"), 
               "Mixed encoding should be detected");
        assert!(detector.detect("test%0%0d%0%0aSet-Cookie: session=hijacked"), 
               "Malformed URL encoding should be detected");
        assert!(detector.detect("test%250d%250aSet-Cookie: session=hijacked"), 
               "Double URL encoding should be detected");
    }
} 