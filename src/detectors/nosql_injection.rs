use crate::detectors::detector_trait::InputDetector;
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    // MongoDB operators
    static ref MONGO_OPERATORS: Regex = Regex::new(r#"\$(?:eq|gt|gte|in|lt|lte|ne|nin|not|exists|type|expr|regex|options|where|text|search|geoWithin|geoIntersects|near|nearSphere|all|elemMatch|size|bitsAllSet|bitsAnySet|bitsAnyClear|bitsAllClear|mod|jsonSchema|slice|meta|comment|rand|natural|function|expr|setOnInsert|setWithoutNewFieldNames)"#).unwrap();
    
    // JavaScript execution in MongoDB
    static ref JS_EXECUTION: Regex = Regex::new(r#"(?i)(?:\$where\s*:|function\s*\(\s*\)\s*\{|\$function\s*:)"#).unwrap();
    
    // JSON injection with MongoDB query operators and array/object manipulation
    static ref JSON_INJECTION: Regex = Regex::new(r#"[\[\{](?:\s*[\"\']?\$\w+[\"\']?\s*:|.*(?:true|false|null).*|\s*\d+\s*)[,\}\]]"#).unwrap();
    
    // NoSQL operator placement in suspicious context
    static ref SUSPICIOUS_CONTEXT: Regex = Regex::new(r#"(password|user|username|account|auth|login|credential).*[=:].*[\{\[].*\$"#).unwrap();
    
    // Common tautology patterns
    static ref TAUTOLOGY_PATTERNS: Regex = Regex::new(r#"(?:\$ne\s*:\s*(?:0|false|null|""|''|\[\]|\{\})|(?:true|1)\s*\$eq\s*:\s*(?:true|1))"#).unwrap();
}

/// Detector for NoSQL injection attacks
/// 
/// Detects attempts to manipulate NoSQL queries with operators and other techniques
pub struct NoSqlInjectionDetector;

impl NoSqlInjectionDetector {
    /// Create a new instance of the NoSQL injection detector
    pub fn new() -> Self {
        NoSqlInjectionDetector
    }
    
    /// Check for MongoDB operators that might be used for injection
    fn contains_mongo_operators(&self, input: &str) -> bool {
        MONGO_OPERATORS.is_match(input)
    }
    
    /// Check for JavaScript execution attempts
    fn contains_js_execution(&self, input: &str) -> bool {
        JS_EXECUTION.is_match(input)
    }
    
    /// Check for MongoDB-specific JSON manipulation
    fn contains_json_manipulation(&self, input: &str) -> bool {
        JSON_INJECTION.is_match(input)
    }
    
    /// Check for NoSQL operators in suspicious contexts
    fn in_suspicious_context(&self, input: &str) -> bool {
        SUSPICIOUS_CONTEXT.is_match(input)
    }
    
    /// Check for tautology patterns (always true conditions)
    fn contains_tautology(&self, input: &str) -> bool {
        TAUTOLOGY_PATTERNS.is_match(input)
    }
    
    /// Check for bracket notation that might indicate object/field manipulation
    fn contains_bracket_notation(&self, input: &str) -> bool {
        // Look for bracket notation that might be used for object manipulation
        // Example: ["$gt"] or ['$gt']
        input.contains("[\"$") || 
        input.contains("['$") || 
        input.contains("[$") || 
        // Check for multiple consecutive brackets that might be JSON manipulation
        (input.contains("[") && input.contains("]") && input.contains("{") && input.contains("}"))
    }
    
    /// Check for direct operator injection
    fn contains_direct_operators(&self, input: &str) -> bool {
        // Direct MongoDB operator injection check
        let operators = [
            "\"$gt\"", "'$gt'", "\"$lt\"", "'$lt'",
            "\"$gte\"", "'$gte'", "\"$lte\"", "'$lte'",
            "\"$ne\"", "'$ne'", "\"$in\"", "'$in'",
            "\"$nin\"", "'$nin'", "\"$exists\"", "'$exists'",
            "\"$regex\"", "'$regex'", "\"$where\"", "'$where'"
        ];
        
        operators.iter().any(|&op| input.contains(op))
    }
    
    /// Check for MongoDB query parameter syntax
    fn contains_query_syntax(&self, input: &str) -> bool {
        // Common MongoDB query parameter syntax patterns
        input.contains("{$") ||
        input.contains("{ $") ||
        input.contains(":{") ||
        input.contains(": {") ||
        // Check for an object with an operator
        (input.contains("{") && input.contains("}") && input.contains("$"))
    }
    
    /// Check for special string patterns used in NoSQL injections
    fn contains_special_strings(&self, input: &str) -> bool {
        // Special strings often used in NoSQL injection attacks
        let suspicious_strings = [
            // JavaScript attack strings
            "sleep(", "while(1)", "ObjectId", 
            // MongoDB attack payloads
            "db.collection", "findOne", "find()", 
            // Command injection via NoSQL
            "exec(", "command(", "shell("
        ];
        
        suspicious_strings.iter().any(|&s| input.contains(s))
    }
}

impl InputDetector for NoSqlInjectionDetector {
    fn detect(&self, input: &str) -> bool {
        // If input is simple and doesn't contain any JSON or special characters, it's likely safe
        if input.len() < 3 || !input.contains('$') && !input.contains('{') && !input.contains('[') {
            return false;
        }
        
        // Check for direct MongoDB operator injection
        if self.contains_direct_operators(input) {
            return true;
        }
        
        // Check for MongoDB query syntax
        if self.contains_query_syntax(input) {
            return true;
        }
        
        // Check for various attack patterns
        if self.contains_mongo_operators(input) || 
           self.contains_js_execution(input) || 
           self.contains_json_manipulation(input) || 
           self.in_suspicious_context(input) || 
           self.contains_tautology(input) || 
           self.contains_bracket_notation(input) ||
           self.contains_special_strings(input) {
            return true;
        }
        
        // Safe input
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_safe_inputs() {
        let detector = NoSqlInjectionDetector::new();
        
        assert!(!detector.detect("normal text"), "Normal text should be safe");
        assert!(!detector.detect("user@example.com"), "Email should be safe");
        assert!(!detector.detect("12345"), "Number should be safe");
        assert!(!detector.detect("John Doe"), "Name should be safe");
        assert!(!detector.detect("simple query"), "Simple query should be safe");
        assert!(!detector.detect("document with brackets: []"), "Simple brackets should be safe");
    }
    
    #[test]
    fn test_mongo_operators() {
        let detector = NoSqlInjectionDetector::new();
        
        assert!(detector.detect("{\"$gt\": \"\"}"), "Basic $gt operator should be detected");
        assert!(detector.detect("{\"username\": {\"$ne\": null}}"), "$ne operator should be detected");
        assert!(detector.detect("{\"password\": {\"$exists\": false}}"), "$exists operator should be detected");
        assert!(detector.detect("{\"$where\": \"this.password == 'password'\"}"), "$where operator should be detected");
        assert!(detector.detect("{field: {\"$regex\": \"^prefix\"}}"), "$regex operator should be detected");
    }
    
    #[test]
    fn test_js_execution() {
        let detector = NoSqlInjectionDetector::new();
        
        assert!(detector.detect("{\"$where\": function() { return true; }}"), "JavaScript function should be detected");
        assert!(detector.detect("{\"$function\": { \"body\": \"return true;\" }}"), "$function should be detected");
        assert!(detector.detect("db.users.find( { $where: function() { return this.username === 'admin' } } )"), "find with $where should be detected");
    }
    
    #[test]
    fn test_tautologies() {
        let detector = NoSqlInjectionDetector::new();
        
        assert!(detector.detect("{\"password\":{\"$ne\":\"\"}}"), "Tautology with empty string should be detected");
        assert!(detector.detect("{\"password\":{\"$ne\":null}}"), "Tautology with null should be detected");
        assert!(detector.detect("{\"active\":{\"$ne\":false}}"), "Tautology with false should be detected");
    }
    
    #[test]
    fn test_json_structure_manipulation() {
        let detector = NoSqlInjectionDetector::new();
        
        assert!(detector.detect("{\"$gt\":\"\"}"), "Direct operator object should be detected");
        assert!(detector.detect("{\"username\":\"admin\", \"$gt\":{}}"), "Mixed valid field with operator should be detected");
        assert!(detector.detect("{\"username[\"$gt\"]\":1}"), "Bracket notation should be detected");
        assert!(detector.detect("{\"username\":{\"$gt\":1}}"), "Nested operator should be detected");
    }
    
    #[test]
    fn test_complex_patterns() {
        let detector = NoSqlInjectionDetector::new();
        
        assert!(detector.detect("{\"username\":{\"$regex\":\"^admin\", \"$options\":\"i\"}}"), "Complex regex pattern should be detected");
        assert!(detector.detect("{\"$or\":[{\"username\":\"admin\"},{\"isAdmin\":true}]}"), "$or operator should be detected");
        assert!(detector.detect("{\"users\":{\"$elemMatch\":{\"name\":\"admin\", \"active\":true}}}"), "$elemMatch should be detected");
        assert!(detector.detect("{\"coords\":{\"$near\":{\"$geometry\":{\"type\":\"Point\",\"coordinates\":[0,0]}}}}"), "Geospatial operators should be detected");
    }
    
    #[test]
    fn test_various_formats() {
        let detector = NoSqlInjectionDetector::new();
        
        assert!(detector.detect("{\n  \"$gt\": \"\"\n}"), "Formatted JSON should be detected");
        assert!(detector.detect("{ \"password\": { $ne: \"\" } }"), "MongoDB shell syntax should be detected");
        assert!(detector.detect("{'username': {'$ne': null}}"), "Single quotes should be detected");
        assert!(detector.detect("username[$ne]=null"), "URL parameter format should be detected");
    }
    
    #[test]
    fn test_real_world_attacks() {
        let detector = NoSqlInjectionDetector::new();
        
        assert!(detector.detect("{\"username\":\"admin\",\"password\":{\"$gt\":\"\"}}"), "Login bypass should be detected");
        assert!(detector.detect("{\"username\":\"admin\",\"$where\":\"sleep(10000)\"}}"), "DoS attack should be detected");
        assert!(detector.detect("{\"username\":\"admin\",\"password\":{\"$in\":[\"password1\",\"password2\",\"password3\"]}}"), "Password guessing should be detected");
        assert!(detector.detect("{\"username\":\"admin\",\"$where\":\"this.data.indexOf('secret') >= 0\"}"), "Data exfiltration should be detected");
    }
} 