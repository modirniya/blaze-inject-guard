use crate::detectors::detector_trait::InputDetector;
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    // Mustache/Handlebars patterns
    static ref MUSTACHE_PATTERN: Regex = Regex::new(r"\{\{.*?\}\}").unwrap();
    static ref HANDLEBARS_TRIPLE_PATTERN: Regex = Regex::new(r"\{\{\{.*?\}\}\}").unwrap();
    
    // Jinja/Twig patterns
    static ref JINJA_EXEC_PATTERN: Regex = Regex::new(r"\{%.*?%\}").unwrap();
    static ref JINJA_PRINT_PATTERN: Regex = Regex::new(r"\{\{.*?(\|\s*safe|\|\s*escape|\|\s*e).*?\}\}").unwrap();
    
    // Expression Language patterns (JSP, Spring, etc.)
    static ref EL_PATTERN: Regex = Regex::new(r"\$\{.*?\}").unwrap();
    static ref JSP_EL_PATTERN: Regex = Regex::new(r"#\{.*?\}").unwrap();
    
    // Angular/Vue patterns
    static ref ANGULAR_BINDING_PATTERN: Regex = Regex::new(r"\{\{.*?\}\}|\[\(.*?\)\]|\(\(.*?\)\)").unwrap();
    static ref VUE_DIRECTIVE_PATTERN: Regex = Regex::new(r#"v-[a-z]+\s*=\s*["'].*?["']"#).unwrap();
    
    // Freemarker patterns
    static ref FREEMARKER_PATTERN: Regex = Regex::new(r"<@.*?>|<#.*?>").unwrap();
    
    // Velocity patterns
    static ref VELOCITY_PATTERN: Regex = Regex::new(r"#[a-zA-Z].*?\(.*?\)|#\{.*?\}|\$[a-zA-Z].*?").unwrap();
    
    // Thymeleaf patterns
    static ref THYMELEAF_PATTERN: Regex = Regex::new(r#"th:[a-z]+\s*=\s*["'].*?["']"#).unwrap();
    
    // Template language injection pattern
    static ref CODE_EXEC_PATTERN: Regex = Regex::new(r#"(\b(system|exec|eval|new|class|forName|getRuntime|ProcessBuilder|load|require)|\.__proto__|\[\s*["'](constructor|prototype)["']\]|\b(__proto__|constructor)\b)"#).unwrap();
    
    // Server Side Template Injection special payloads
    static ref SSTI_PAYLOADS: Regex = Regex::new(r#"(\{\{.*?7\s*[*×x]\s*7.*?\}\}|\{\{.*?["'].\s*\+\s*["'].\s*\+.*?\}\}|\$\{.*?[0-9]+\s*[*×x]\s*[0-9]+.*?\})"#).unwrap();
}

/// Detector for Template Injection attacks
///
/// Detects attempts to inject template syntax into user inputs, which could lead to
/// RCE (Remote Code Execution) through template engine exploitation.
pub struct TemplateInjectionDetector;

impl TemplateInjectionDetector {
    /// Create a new instance of the template injection detector
    pub fn new() -> Self {
        TemplateInjectionDetector
    }
    
    /// Check for Mustache/Handlebars template syntax
    fn contains_mustache_syntax(&self, input: &str) -> bool {
        MUSTACHE_PATTERN.is_match(input) || HANDLEBARS_TRIPLE_PATTERN.is_match(input)
    }
    
    /// Check for Jinja/Twig template syntax
    fn contains_jinja_syntax(&self, input: &str) -> bool {
        JINJA_EXEC_PATTERN.is_match(input) || 
        input.contains("{{") && (
            input.contains("|") ||
            input.contains(".__class__") || 
            input.contains(".__mro__") || 
            input.contains(".__globals__") || 
            input.contains(".__base__") || 
            input.contains("__builtins__") ||
            input.contains("config.items()")
        )
    }
    
    /// Check for Expression Language (EL) template syntax
    fn contains_el_syntax(&self, input: &str) -> bool {
        EL_PATTERN.is_match(input) || JSP_EL_PATTERN.is_match(input)
    }
    
    /// Check for JS framework template syntax (Angular, Vue)
    fn contains_js_framework_syntax(&self, input: &str) -> bool {
        ANGULAR_BINDING_PATTERN.is_match(input) ||
        (VUE_DIRECTIVE_PATTERN.is_match(input) && 
         (input.contains("constructor") || input.contains("__proto__")))
    }
    
    /// Check for Java-based template engines (Freemarker, Velocity)
    fn contains_java_template_syntax(&self, input: &str) -> bool {
        FREEMARKER_PATTERN.is_match(input) || 
        VELOCITY_PATTERN.is_match(input) || 
        THYMELEAF_PATTERN.is_match(input)
    }
    
    /// Check for code execution patterns in templates
    fn contains_code_execution(&self, input: &str) -> bool {
        CODE_EXEC_PATTERN.is_match(input)
    }
    
    /// Check for known SSTI test payloads
    fn contains_ssti_test_payloads(&self, input: &str) -> bool {
        SSTI_PAYLOADS.is_match(input) ||
        (input.contains("{{") && input.contains("}}") && (
            input.contains("7*7") || 
            input.contains("7×7") || 
            input.contains("7x7")
        )) ||
        (input.contains("${") && input.contains("}") && (
            input.contains("7*7") || 
            input.contains("7×7") || 
            input.contains("7x7") ||
            input.contains("System") ||
            input.contains("getRuntime") ||
            input.contains("ProcessBuilder")
        ))
    }
}

impl InputDetector for TemplateInjectionDetector {
    fn detect(&self, input: &str) -> bool {
        if input.trim().is_empty() || input.len() < 3 {
            return false;
        }
        
        // Check for common SSTI test payloads
        if self.contains_ssti_test_payloads(input) {
            return true;
        }
        
        // Check for Mustache/Handlebars
        if self.contains_mustache_syntax(input) {
            return true;
        }
        
        // Check for Jinja/Twig
        if self.contains_jinja_syntax(input) {
            return true;
        }
        
        // Check for Expression Language
        if self.contains_el_syntax(input) {
            return true;
        }
        
        // Check for JavaScript frameworks
        if self.contains_js_framework_syntax(input) {
            return true;
        }
        
        // Check for explicit Vue directive with constructor
        if input.contains("v-bind") && input.contains("constructor") {
            return true;
        }
        
        // Check for Java-based templates
        if self.contains_java_template_syntax(input) {
            return true;
        }
        
        // Ruby ERB
        if input.contains("<%") && input.contains("%>") {
            return true;
        }
        
        // Smarty template engine
        if (input.contains("{") && input.contains("}")) && 
           (input.contains("smarty") || input.contains("{php}")) {
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
        let detector = TemplateInjectionDetector::new();
        
        assert!(!detector.detect("Hello world"), "Regular text should not be flagged");
        assert!(!detector.detect("User: John Smith"), "Simple text should not be flagged");
        assert!(!detector.detect("He said {this is in braces}"), "Text with braces should not be flagged");
        assert!(!detector.detect("7*7=49"), "Mathematical expression should not be flagged");
        assert!(!detector.detect("<p>Regular HTML content</p>"), "HTML should not be flagged");
    }
    
    #[test]
    fn test_mustache_injection() {
        let detector = TemplateInjectionDetector::new();
        
        assert!(detector.detect("{{7*7}}"), "Basic Mustache injection should be detected");
        assert!(detector.detect("{{ constructor.constructor('return process')() }}"), "Mustache RCE should be detected");
        assert!(detector.detect("{{{html}}}"), "Handlebars triple stache should be detected");
        assert!(detector.detect("{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.constructor \"constructor\")}}{{this.pop}}{{#with string.constructor.prototype.toString=conslist.pop}}{{#with \"constructor\"}}{{#with this}}{{#with this.constructor(\"return process.mainModule.require('child_process')\")()}}{{#with this.exec(\"whoami\")}}{{this}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}"), "Complex Handlebars RCE should be detected");
    }
    
    #[test]
    fn test_jinja_injection() {
        let detector = TemplateInjectionDetector::new();
        
        assert!(detector.detect("{{ 7*7 }}"), "Basic Jinja injection should be detected");
        assert!(detector.detect("{% for x in range(1,10) %}{{ x }}{% endfor %}"), "Jinja for loop should be detected");
        assert!(detector.detect("{{ \"hello\"|upper }}"), "Jinja filter should be detected");
        assert!(detector.detect("{{ config.items() }}"), "Jinja config access should be detected");
        assert!(detector.detect("{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')|attr('\\x5f\\x5fbuiltins\\x5f\\x5f')|attr('\\x5f\\x5fimport\\x5f\\x5f')('os')|attr('popen')('id')|attr('read')()}}"), "Complex Jinja attack should be detected");
        assert!(detector.detect("{{ ''.__class__.__mro__[1].__subclasses__() }}"), "Jinja class lookup attack should be detected");
    }
    
    #[test]
    fn test_el_injection() {
        let detector = TemplateInjectionDetector::new();
        
        assert!(detector.detect("${7*7}"), "Basic EL injection should be detected");
        assert!(detector.detect("${System.getProperty('user.home')}"), "Basic EL system property should be detected");
        assert!(detector.detect("${session.setAttribute(\"a\",\"b\")}"), "EL session manipulation should be detected");
        assert!(detector.detect("${runtime.exec('cat /etc/passwd')}"), "EL command execution should be detected");
        assert!(detector.detect("#{runtime.exec('cat /etc/passwd')}"), "JSP EL command execution should be detected");
        assert!(detector.detect("${T(java.lang.Runtime).getRuntime().exec('calc')}"), "Spring EL command execution should be detected");
    }
    
    #[test]
    fn test_other_templates() {
        let detector = TemplateInjectionDetector::new();
        
        // Vue/Angular
        assert!(detector.detect("{{constructor.constructor('alert(1)')()}}"), "Angular constructor attack should be detected");
        assert!(detector.detect("<div v-bind:class=\"__proto__.constructor.constructor('alert(1)')()\""), "Vue directive attack should be detected");
        
        // FreeMarker
        assert!(detector.detect("<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"ls\")}"), "FreeMarker command execution should be detected");
        
        // Velocity
        assert!(detector.detect("#set($str=$class.inspect(\"java.lang.String\").type)#set($chr=$class.inspect(\"java.lang.Character\").type)$str.valueOf($chr.toChars(99))"), "Velocity attack should be detected");
        
        // ERB
        assert!(detector.detect("<%= system('whoami') %>"), "ERB command execution should be detected");
        
        // Smarty
        assert!(detector.detect("{php}echo `id`;{/php}"), "Smarty PHP execution should be detected");
    }
} 