/// The core trait that all injection detectors must implement
/// 
/// This follows the Open-Closed Principle - allowing for new detector 
/// implementations without modifying existing code
pub trait InputDetector {
    /// Detect if the provided input string contains malicious patterns
    /// 
    /// # Arguments
    /// * `input` - The string to analyze for malicious patterns
    /// 
    /// # Returns
    /// * `bool` - True if the input is detected as malicious, false otherwise
    fn detect(&self, input: &str) -> bool;
} 