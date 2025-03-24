use crate::detectors::detector_trait::InputDetector;
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    // Detect newlines in various forms
    static ref NEWLINES: Regex = Regex::new(r"[\r\n]|(%0[aAdD])|(%0a%0d)|(\\\r)|(\\\n)|(\\n)|(\\r)").unwrap();
    
    // Log format breaking characters and keywords
    static ref FORMAT_BREAKING: Regex = Regex::new(r"(\[(INFO|ERROR|WARN|DEBUG|CRITICAL|FATAL|NOTICE|TRACE)\])|(\d{4}-\d{2}-\d{2})|(\d{2}:\d{2}:\d{2})|(log(ged)?[ _-]?in)|(log(ged)?[ _-]?out)|(auth(enticated|orized)?)|(user[ :=])").unwrap();
    
    // Log entry markers 
    static ref LOG_ENTRY_MARKERS: Regex = Regex::new(r"(\[.*?\])|(\{.*?\})|(\|)|(\w+:)|(\s-\s)|(Logger)|(timestamp)").unwrap();
    
    // Common logging framework patterns
    static ref LOGGING_PATTERNS: Regex = Regex::new(r"(log4j)|(logback)|(slf4j)|(winston)|(morgan)|(console\.log)|(System\.Logger)|(python.*(warn|error|info))").unwrap();
    
    // Suspicious control characters
    static ref CONTROL_CHARS: Regex = Regex::new(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]").unwrap();
}

/// Detector for Log Injection/Log Forging attacks
/// 
/// Detects attempts to insert fake log entries by manipulating input to include newlines 
/// and log formatting characters that could break logging systems
pub struct LogInjectionDetector;

impl LogInjectionDetector {
    /// Create a new instance of the Log Injection detector
    pub fn new() -> Self {
        LogInjectionDetector
    }
    
    /// Check for newlines in various forms - CR, LF, encoded, escaped
    fn contains_newlines(&self, input: &str) -> bool {
        NEWLINES.is_match(input)
    }
    
    /// Check for log format breaking characters
    fn contains_format_breaking(&self, input: &str) -> bool {
        FORMAT_BREAKING.is_match(input)
    }
    
    /// Check for log entry markers that might indicate an attempt to forge entries
    fn contains_log_markers(&self, input: &str) -> bool {
        LOG_ENTRY_MARKERS.is_match(input)
    }
    
    /// Check for keywords related to logging frameworks
    fn contains_logging_framework_patterns(&self, input: &str) -> bool {
        LOGGING_PATTERNS.is_match(input)
    }
    
    /// Check for suspicious control characters that might be used to break log formatting
    fn contains_control_chars(&self, input: &str) -> bool {
        CONTROL_CHARS.is_match(input)
    }
    
    /// Check for encoded sequences that might evade detection
    fn contains_encoded_sequences(&self, input: &str) -> bool {
        // Look for various encodings of control characters or newlines
        // URL encoding, Unicode escapes, hex escapes, etc.
        input.contains("%") || 
        input.contains("\\u00") ||
        input.contains("\\x0") ||
        input.contains("\\U000") ||
        (input.contains("\\") && (input.contains("n") || input.contains("r")))
    }
    
    /// Check for potential attempts to spoof log entries with timestamps
    fn contains_timestamp_spoofing(&self, input: &str) -> bool {
        // Common timestamp formats
        let timestamp_patterns = [
            r"\d{4}-\d{2}-\d{2}", // ISO date (YYYY-MM-DD)
            r"\d{2}:\d{2}:\d{2}", // time (HH:MM:SS)
            r"\d{1,2}/\d{1,2}/\d{2,4}", // MM/DD/YY or MM/DD/YYYY
            r"\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}", // syslog format (e.g., "Oct 15 14:33:21")
            r"\d{1,2}-\w{3}-\d{4}", // DD-Mon-YYYY
        ];
        
        // Check for standalone timestamps
        let timestamp_match = timestamp_patterns.iter().any(|pattern| {
            Regex::new(pattern).unwrap().is_match(input)
        });
        
        // If a timestamp is found, check if it's part of a suspicious log pattern
        if timestamp_match {
            // Timestamps with log structure markers or log levels are more suspicious
            if self.contains_log_markers(input) || self.contains_injected_log_levels(input) {
                return true;
            }
            
            // Timestamp followed by common log message patterns
            let timestamp_with_message_patterns = [
                r"\d{2}:\d{2}:\d{2}.*user",
                r"\d{2}:\d{2}:\d{2}.*login",
                r"\d{2}:\d{2}:\d{2}.*logged",
                r"\d{2}:\d{2}:\d{2}.*auth",
                r"\d{2}:\d{2}:\d{2}.*success",
                r"\d{2}:\d{2}:\d{2}.*fail",
                r"\d{4}-\d{2}-\d{2}.*user",
                r"\d{4}-\d{2}-\d{2}.*admin",
                r"\d{4}-\d{2}-\d{2}.*access",
            ];
            
            return timestamp_with_message_patterns.iter().any(|pattern| {
                Regex::new(pattern).unwrap().is_match(input)
            });
        }
        
        false
    }
    
    /// Check for attempts to inject common log levels
    fn contains_injected_log_levels(&self, input: &str) -> bool {
        // Common log levels
        let log_levels = [
            "INFO", "ERROR", "WARN", "WARNING", "DEBUG", "TRACE", 
            "CRITICAL", "FATAL", "NOTICE", "SEVERE", "FINE"
        ];
        
        log_levels.iter().any(|&level| {
            let level_pattern = format!(r"(?i)\[{}\]|{}\s+:|{}\s+-|{}\s+\||\b{}:", level, level, level, level, level);
            Regex::new(&level_pattern).unwrap().is_match(input)
        })
    }
    
    /// Check for injection of log events or messages
    fn contains_event_injection(&self, input: &str) -> bool {
        // Common log event texts
        let event_patterns = [
            r"(?i)user\s+(session\s+)?(validated|authenticated|logged\s+(in|out))",
            r"(?i)(authentication|login)\s+(successful|failed|attempt)",
            r"(?i)password\s+(changed|expired|incorrect|reset)",
            r"(?i)account\s+(locked|unlocked|created|deleted)",
            r"(?i)admin\s+privileges\s+(granted|revoked)",
            r"(?i)access\s+(granted|denied|revoked)",
            r"(?i)firewall\s+(enabled|disabled|breach)",
            r"(?i)system\s+(reboot|shutdown|start|initialization)"
        ];
        
        event_patterns.iter().any(|pattern| {
            Regex::new(pattern).unwrap().is_match(input)
        })
    }
}

impl InputDetector for LogInjectionDetector {
    fn detect(&self, input: &str) -> bool {
        // If input is simple and doesn't contain suspicious characters, it's likely safe
        if input.len() < 3 || (!input.contains('\n') && !input.contains('\r') && !input.contains('%') && !input.contains('\\')) {
            // Even if it doesn't have suspicious characters, still check for timestamp and log level combinations
            if self.contains_timestamp_spoofing(input) {
                return true;
            }
            
            return false;
        }
        
        // Check for newlines - the most basic form of log injection
        if self.contains_newlines(input) {
            // If it contains newlines AND any other suspicious patterns, it's almost certainly malicious
            if self.contains_format_breaking(input) || 
               self.contains_log_markers(input) || 
               self.contains_logging_framework_patterns(input) ||
               self.contains_injected_log_levels(input) ||
               self.contains_event_injection(input) {
                return true;
            }
            
            // Even just newlines could be suspicious in some contexts
            return true;
        }
        
        // Check for other suspicious patterns
        if self.contains_encoded_sequences(input) {
            if self.contains_format_breaking(input) || 
               self.contains_log_markers(input) ||
               self.contains_timestamp_spoofing(input) ||
               self.contains_injected_log_levels(input) ||
               self.contains_event_injection(input) {
                return true;
            }
        }
        
        // Check for control characters that might manipulate logs
        if self.contains_control_chars(input) {
            return true;
        }
        
        // Time with pipe format is particularly common in logs
        if input.contains("|") && Regex::new(r"\d{2}:\d{2}:\d{2}").unwrap().is_match(input) {
            return true;
        }
        
        // Combination of timestamp spoofing with log levels is almost certainly malicious
        if self.contains_timestamp_spoofing(input) && self.contains_injected_log_levels(input) {
            return true;
        }
        
        // If multiple logging-specific patterns appear, it's likely an injection attempt
        let suspicious_pattern_count = [
            self.contains_format_breaking(input),
            self.contains_log_markers(input),
            self.contains_logging_framework_patterns(input),
            self.contains_timestamp_spoofing(input),
            self.contains_injected_log_levels(input),
            self.contains_event_injection(input)
        ].iter().filter(|&&x| x).count();
        
        // If there are multiple suspicious patterns, it's likely an attack
        suspicious_pattern_count >= 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_safe_inputs() {
        let detector = LogInjectionDetector::new();
        
        assert!(!detector.detect("normal text"), "Normal text should be safe");
        assert!(!detector.detect("user@example.com"), "Email should be safe");
        assert!(!detector.detect("12345"), "Number should be safe");
        assert!(!detector.detect("John Doe"), "Name should be safe");
        assert!(!detector.detect("Simple log message"), "Simple message should be safe");
    }
    
    #[test]
    fn test_newline_injection() {
        let detector = LogInjectionDetector::new();
        
        assert!(detector.detect("username\nUser logged out\nadmin logged in"), "Basic newline injection should be detected");
        assert!(detector.detect("username\rUser logged out\radmin logged in"), "CR injection should be detected");
        assert!(detector.detect("username%0AUser logged out%0Aadmin logged in"), "URL-encoded LF should be detected");
        assert!(detector.detect("username%0DUser logged out%0Dadmin logged in"), "URL-encoded CR should be detected");
        assert!(detector.detect("username\\nUser logged out\\nadmin logged in"), "Escaped newline should be detected");
        assert!(detector.detect("username\\rUser logged out\\radmin logged in"), "Escaped CR should be detected");
    }
    
    #[test]
    fn test_log_format_injection() {
        let detector = LogInjectionDetector::new();
        
        assert!(detector.detect("[INFO] 2023-04-01 User action completed"), "Log level with timestamp should be detected");
        assert!(detector.detect("user=admin\\nuser=attacker"), "Format breaking with escape should be detected");
        assert!(detector.detect("2023-01-01 12:34:56 - User authenticated"), "Timestamp with action should be detected");
        assert!(detector.detect("username | [ERROR] Authentication failed"), "Log marker with level should be detected");
    }
    
    #[test]
    fn test_combined_patterns() {
        let detector = LogInjectionDetector::new();
        
        assert!(detector.detect("username%0A[ERROR] 2023-04-01 12:34:56 User admin granted privileges"), "Combined pattern should be detected");
        assert!(detector.detect("successful login\\n{\"level\":\"error\",\"msg\":\"security breach\"}"), "JSON log format injection should be detected");
        assert!(detector.detect("normal input%0AWARNING - System shutdown initiated"), "Warning with action should be detected");
        assert!(detector.detect("user%0d%0aUser logged out%0d%0aadmin logged in"), "Multiple line breaks with user events should be detected");
    }
    
    #[test]
    fn test_encoded_patterns() {
        let detector = LogInjectionDetector::new();
        
        assert!(detector.detect("user%00name"), "Null byte should be detected");
        assert!(detector.detect("user\\u000Aname"), "Unicode escaped LF should be detected");
        assert!(detector.detect("user\\x0Aname"), "Hex escaped LF should be detected");
        assert!(detector.detect("user%25%30%41name"), "Double-encoded newline should be detected");
        assert!(detector.detect("user%0d%0aUser logged out%0d%0aadmin logged in"), "URL-encoded CRLF sequence should be detected");
    }
    
    #[test]
    fn test_control_characters() {
        let detector = LogInjectionDetector::new();
        
        assert!(detector.detect("user\x01name"), "Control character SOH should be detected");
        assert!(detector.detect("user\x07name"), "Bell character should be detected");
        assert!(detector.detect("user\x1Bname"), "Escape character should be detected");
        assert!(detector.detect("user\x0Bname"), "Vertical tab should be detected");
        assert!(detector.detect("user\x0Cname"), "Form feed should be detected");
    }
    
    #[test]
    fn test_log_level_injection() {
        let detector = LogInjectionDetector::new();
        
        assert!(detector.detect("[INFO] User activity recorded"), "INFO level should be detected");
        assert!(detector.detect("ERROR: Database connection failed"), "ERROR level should be detected");
        assert!(detector.detect("WARNING | Access attempt from unauthorized IP"), "WARNING with pipe should be detected");
        assert!(detector.detect("DEBUG - Entering function with parameters"), "DEBUG with dash should be detected");
        assert!(detector.detect("FATAL: System crash imminent"), "FATAL level should be detected");
    }
    
    #[test]
    fn test_timestamp_spoofing() {
        let detector = LogInjectionDetector::new();
        
        assert!(detector.detect("2023-04-01 14:30:00 User activity"), "ISO timestamp should be detected");
        assert!(detector.detect("Apr 1 14:30:00 User activity"), "Syslog timestamp should be detected");
        assert!(detector.detect("01/04/2023 14:30:00 User activity"), "Slash format date should be detected");
        assert!(detector.detect("01-Apr-2023 User activity"), "Day-Month-Year format should be detected");
        assert!(detector.detect("14:30:00 User activity"), "Time only should be detected");
    }
    
    #[test]
    fn test_event_injection() {
        let detector = LogInjectionDetector::new();
        
        assert!(detector.detect("User session validated successfully"), "Session validation should be detected");
        assert!(detector.detect("Authentication failed for user"), "Auth failed should be detected");
        assert!(detector.detect("Password reset for account"), "Password reset should be detected");
        assert!(detector.detect("Admin privileges granted to user"), "Admin privileges should be detected");
        assert!(detector.detect("System reboot initiated by user"), "System reboot should be detected");
    }
    
    #[test]
    fn test_real_world_attacks() {
        let detector = LogInjectionDetector::new();
        
        assert!(detector.detect("username%0d%0a[INFO] 2023-04-01 12:34:56 admin logged in"), "Real-world admin login injection should be detected");
        assert!(detector.detect("user\\n[ERROR] 2023-04-01 12:34:56 - Critical security breach"), "Security breach injection should be detected");
        assert!(detector.detect("normal\\r\\n[WARNING] Firewall disabled"), "Firewall warning injection should be detected");
        assert!(detector.detect("user%0d%0a2023-04-01 12:34:56 | NOTICE | Password for admin changed"), "Password change notice should be detected");
        assert!(detector.detect("username%0A14:30:45 DEBUG Account unlocked after multiple failed attempts"), "Account unlock debug message should be detected");
    }
} 