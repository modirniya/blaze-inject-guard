# blaz-inject-guard
High-performance Rust library for detecting injection attacks and input vulnerabilities with minimal overhead.

# Blaz Inject Guard API

High-performance Rust library for detecting injection attacks and input vulnerabilities with minimal overhead.

## Overview

Blaz Inject Guard is designed to detect various types of injection attacks in user inputs. It follows the Open-Closed Principle, making it easy to add new detector types without modifying existing code.

Currently implemented detection types:
- Command Injection Detection
- Cross-Site Scripting (XSS) Detection
- LDAP Injection Detection
- XML Injection/XXE Detection
- Template Injection Detection
- HTML Injection Detection
- Path Traversal Detection
- Header Injection Detection
- CSV Injection Detection
- Regular Expression DoS (ReDoS) Detection
- NoSQL Injection Detection
- Log Injection/Log Forging Detection

## Getting Started

### Prerequisites

- Rust and Cargo (latest stable version)

### Running the API

1. Clone the repository
2. Run the server:

```bash
cargo run
```

3. The API will be available at `http://0.0.0.0:8080`

## API Endpoints

- `GET /` - Welcome endpoint
- `GET /health` - Health check endpoint
- `POST /detect/command` - Detect command injection in the provided input
- `POST /detect/xss` - Detect cross-site scripting (XSS) in the provided input
- `POST /detect/ldap` - Detect LDAP injection in the provided input
- `POST /detect/xml` - Detect XML Injection/XXE in the provided input
- `POST /detect/template` - Detect template injection in the provided input
- `POST /detect/html` - Detect HTML injection in the provided input
- `POST /detect/path` - Detect path traversal in the provided input
- `POST /detect/header` - Detect HTTP header injection in the provided input
- `POST /detect/csv` - Detect CSV formula injection in the provided input
- `POST /detect/redos` - Detect Regular Expression DoS (ReDoS) in the provided input
- `POST /detect/nosql` - Detect NoSQL injection in the provided input
- `POST /detect/log` - Detect Log Injection/Log Forging in the provided input
- `POST /detect/comprehensive` - Run all available detectors on the input
- `POST /detect/batch` - Run selected detectors on multiple inputs

### Comprehensive Detection

The comprehensive detection endpoint runs all available detectors on the provided input and returns a combined result.

Example request:
```bash
curl -X POST http://0.0.0.0:8080/detect/comprehensive \
  -H "Content-Type: application/json" \
  -d '{"content": "Hello; rm -rf /"}'
```

Example response:
```json
{
  "command_injection": false,
  "xss": false,
  "ldap_injection": false,
  "xml_injection": false,
  "template_injection": false,
  "html_injection": false,
  "path_traversal": false,
  "header_injection": false,
  "csv_injection": false,
  "redos": false,
  "nosql_injection": false,
  "log_injection": false,
  "is_safe": true
}
```

### Batch Detection

The batch detection endpoint allows you to process multiple inputs and selectively run specific detectors.

Example request:
```bash
curl -X POST http://0.0.0.0:8080/detect/batch \
  -H "Content-Type: application/json" \
  -d '{
    "contents": ["Hello; rm -rf /", "<script>alert(1)</script>"],
    "detectors": {
      "command_injection": true,
      "xss": true,
      "ldap_injection": false
    }
  }'
```

Example response:
```json
{
  "results": [
    {
      "command_injection": false,
      "xss": false,
      "path_traversal": false,
      "is_safe": true
    },
    {
      "command_injection": true,
      "xss": false,
      "path_traversal": false,
      "is_safe": false
    },
    {
      "command_injection": false,
      "xss": true,
      "path_traversal": false,
      "is_safe": false
    }
  ]
}
```

Note: The batch detection response only includes results for the selected detectors. Detectors set to `false` in the request will not be run and their results will not appear in the response.

### Command Injection Detection

Detects attempts to inject OS commands into text inputs that might be passed to system shells.

Example request:
```bash
curl -X POST http://0.0.0.0:8080/detect/command \
  -H "Content-Type: application/json" \
  -d '{"content": "Hello; rm -rf /"}'
```

Example response:
```json
{
  "is_malicious": false,
  "detector_type": "command_injection"
}
```

### Cross-Site Scripting (XSS) Detection

Detects attempts to inject malicious JavaScript that could execute in browsers.

Example request:
```bash
curl -X POST http://0.0.0.0:8080/detect/xss \
  -H "Content-Type: application/json" \
  -d '{"content": "<script>alert(1)</script>"}'
```

Example response:
```json
{
  "is_malicious": false,
  "detector_type": "xss"
}
```

### LDAP Injection Detection

Detects attempts to manipulate LDAP queries through user input.

Example request:
```bash
curl -X POST http://0.0.0.0:8080/detect/ldap \
  -H "Content-Type: application/json" \
  -d '{"content": "admin)(|(password=*)"}'
```

Example response:
```json
{
  "is_malicious": false,
  "detector_type": "ldap_injection"
}
```

### XML Injection/XXE Detection

**Endpoint**: `POST /detect/xml`

**Request**:
```json
{
  "content": "<your XML string to check>"
}
```

**Response**:
```json
{
  "is_malicious": true|false,
  "detector_type": "xml_injection"
}
```

This detector identifies attempts to attack XML parsers through external entity references, specifically focusing on:
- DOCTYPE declarations and ENTITY tags
- External entity references using SYSTEM or PUBLIC identifiers
- XML bombs (billion laughs attack)
- Inclusion of sensitive file paths through XXE

### Template Injection Detection

**Endpoint**: `POST /detect/template`

**Request**:
```json
{
  "content": "<your template string to check>"
}
```

**Response**:
```json
{
  "is_malicious": true|false,
  "detector_type": "template_injection"
}
```

This detector identifies attempts to exploit template engines by injecting template syntax, which could lead to server-side template injection (SSTI) vulnerabilities, focusing on:
- Common syntax patterns for popular template engines (Mustache, Handlebars, Jinja, Twig, etc.)
- Expression Language (EL) injections often used in Java environments
- Known SSTI attack patterns that can lead to Remote Code Execution (RCE)
- Test payloads that are commonly used to identify template injection vulnerabilities (like {{7*7}})

### HTML Injection Detection

**Endpoint**: `POST /detect/html`

**Request**:
```json
{
  "content": "<your HTML string to check>"
}
```

**Response**:
```json
{
  "is_malicious": true|false,
  "detector_type": "html_injection"
}
```

This detector identifies HTML that could manipulate page structure, overlay, hide, or replace existing content, focusing on:
- Position and layout manipulation (absolute positioning, full-width/height elements)
- Dangerous HTML tags (iframe, script, object, embed, etc.)
- Content hiding techniques (opacity:0, visibility:hidden, display:none)
- Event handlers that could execute JavaScript
- Document structure manipulation attempts

### Path Traversal Detection

**Endpoint**: `POST /detect/path`

**Request**:
```json
{
  "content": "<your path or URL to check>"
}
```

**Response**:
```json
{
  "is_malicious": true|false,
  "detector_type": "path_traversal"
}
```

This detector identifies attempts to manipulate file paths to access unauthorized files, focusing on:
- Directory traversal sequences (`../`, `..\\`, etc.)
- URL and double-encoded traversal patterns (`%2e%2e%2f`, `%252e%252e%252f`)
- Access attempts to sensitive system files and directories
- Path normalization bypass techniques
- Protocol handlers that could access local files (`file://`, `php://`, etc.)

### Header Injection Detection

**Endpoint**: `POST /detect/header`

**Request**:
```json
{
  "content": "<your header value to check>"
}
```

**Response**:
```json
{
  "is_malicious": true|false,
  "detector_type": "header_injection"
}
```

This detector identifies attempts to inject newlines into HTTP headers to add unauthorized headers, focusing on:
- CR/LF characters (`\r\n`, `%0d%0a`) that could lead to HTTP response splitting
- Session hijacking attempts via injected `Set-Cookie` headers
- Security header manipulation via injected security policy headers
- Authorization header injection attempts
- Common header injection patterns in both plain and URL-encoded formats

### CSV Injection Detection

**Endpoint**: `POST /detect/csv`

**Request**:
```json
{
  "content": "<your CSV content to check>"
}
```

**Response**:
```json
{
  "is_malicious": true|false,
  "detector_type": "csv_injection"
}
```

This detector identifies formula injections that could execute when a CSV file is opened in spreadsheet applications, focusing on:
- Common formula markers (`=`, `+`, `-`, `@`) at the start of fields
- Dangerous spreadsheet functions (e.g., `HYPERLINK`, `DDE`, `WEBSERVICE`)
- Excel and Google Sheets function patterns that could lead to data exfiltration
- Macro and shell command execution attempts
- Obfuscation techniques used to hide formula injections

### Regular Expression DoS (ReDoS) Detection

**Endpoint**: `POST /detect/redos`

**Request**:
```json
{
  "content": "<your input to check for ReDoS patterns>"
}
```

**Response**:
```json
{
  "is_malicious": true|false,
  "detector_type": "redos"
}
```

This detector identifies input patterns that might cause catastrophic backtracking in regex engines, focusing on:
- Long repetitions of characters (e.g., `aaaaaaaaaaaaaaaaa!`)
- Nested repetition patterns (e.g., `(a+)+b`)
- Alternation with repetition (e.g., `(foo|bar|baz)+`)
- Complex patterns with multiple quantifiers
- Real-world examples that could cause ReDoS in email, URL, and date validation
- Input with suspiciously low character diversity or high repetition

### NoSQL Injection Detection

**Endpoint**: `POST /detect/nosql`

**Request**:
```json
{
  "content": "<your input to check for NoSQL injection>"
}
```

**Response**:
```json
{
  "is_malicious": true|false,
  "detector_type": "nosql_injection"
}
```

This detector identifies attempts to manipulate NoSQL database queries, focusing on:
- MongoDB operator injection (e.g., `$gt`, `$ne`, `$where`, etc.)
- Query structure manipulation to bypass authentication
- JavaScript code execution via `$where` or function operators
- Tautologies and always-true conditions to bypass filters
- JSON structure manipulation and bracket notation attacks
- Special MongoDB query syntax and patterns used in NoSQL injection attacks

### Log Injection/Log Forging Detection

**Endpoint**: `POST /detect/log`

**Request**:
```json
{
  "content": "<your input to check for log injection>"
}
```

**Response**:
```json
{
  "is_malicious": true|false,
  "detector_type": "log_injection"
}
```

This detector identifies attempts to manipulate log files or log entries by injecting fake log events, focusing on:
- Line break insertion (CR/LF) in various encodings (raw, URL-encoded, escaped)
- Log formatting patterns that might create false entries (timestamps, log levels, etc.)
- Common log event spoofing patterns (login events, authentication messages, etc.)
- Control characters that could manipulate log output
- Combinations of patterns that indicate sophisticated log injection attempts
- Log structure markers and formatting tokens that might break log parsers

## Architecture

The project follows the Open-Closed Principle by using a common trait interface (`InputDetector`) that all detectors implement. This allows adding new detection types without modifying existing code.

### Detection Algorithms

#### Command Injection
Focuses on detecting shell metacharacters (;, &&, |, backticks) and common command patterns.

#### Cross-Site Scripting (XSS)
Looks for script tags, event handlers, javascript: URLs, and various obfuscation techniques.

#### LDAP Injection
Focuses on detecting LDAP special characters and operators (like `)(`, `*)(`, `|` and `&`), unbalanced parentheses, and attribute manipulation.

#### XML Injection/XXE

The XML Injection/XXE detector focuses on identifying:

1. **DOCTYPE and ENTITY declarations**: Detects patterns that could lead to XXE vulnerabilities, especially when combined with SYSTEM or PUBLIC identifiers.

2. **External entity references**: Identifies attempts to reference external resources via protocols like file:///,  http://, expect://, php://, etc.

3. **Sensitive file paths**: Checks for references to common sensitive system files that attackers might try to access via XXE.

4. **XML bombs**: Detects patterns like the "billion laughs" attack that cause XML parsers to expand entities recursively, leading to denial of service.

5. **Encoded attacks**: Recognizes XXE attack patterns even when URL encoded, HTML entity encoded, or otherwise obfuscated.

### Template Injection Detection

The Template Injection detector focuses on identifying:

1. **Template expression syntax**: Detects patterns specific to various template engines, including Mustache/Handlebars (`{{...}}`), Jinja/Twig (`{%...%}`, `{{...}}`), Expression Language (`${...}`), and others.

2. **Code execution patterns**: Identifies attempts to access dangerous methods or properties that could lead to code execution, such as constructor references, eval functions, or system calls.

3. **Common test payloads**: Recognizes common Server-Side Template Injection (SSTI) test payloads like `{{7*7}}` or `${7*7}` that are used to probe for vulnerabilities.

4. **Framework-specific exploits**: Detects specific exploitation techniques for popular frameworks such as Angular, Vue, FreeMarker, Velocity, Thymeleaf, and ERB.

5. **Object traversal**: Identifies attempts to traverse object properties to access sensitive functionality, like Python's `__class__`, `__globals__`, or JavaScript's `__proto__` and `constructor`.

### HTML Injection Detection

The HTML Injection detector focuses on identifying:

1. **Layout manipulation**: Detects HTML with absolute or fixed positioning, high z-index values, or full-width/height elements that could overlay existing content.

2. **Content hiding techniques**: Identifies CSS properties that could hide content, such as opacity:0, visibility:hidden, or display:none.

3. **Dangerous HTML tags**: Checks for risky elements like iframe, script, object, embed, link, base, and others that might modify page behavior.

4. **Event handlers**: Recognizes inline JavaScript event handlers that could execute malicious code.

5. **Page structure modification**: Detects attempts to manipulate the overall document structure using HTML tags like html, head, or body.

### Path Traversal Detection

The Path Traversal detector focuses on identifying:

1. **Directory traversal sequences**: Recognizes patterns like `../`, `..\\`, or variations that navigate up the directory structure to access files outside the intended directory.

2. **Encoded traversal attempts**: Detects URL encoded (`%2e%2e%2f`), double-encoded, or otherwise obfuscated path traversal techniques designed to bypass security filters.

3. **Sensitive file access**: Identifies attempts to access common sensitive system files like `/etc/passwd`, `/etc/shadow`, or Windows system files.

4. **Protocol handler abuse**: Detects use of protocols like `file://`, `phar://`, or `php://` that might be used to access files on the filesystem.

5. **Null byte injection**: Recognizes null byte (`%00`) injection techniques used to truncate filenames and bypass extension validation.

6. **Path normalization bypasses**: Identifies techniques that exploit path normalization like `....//....//` or `./..` to confuse path resolvers.

### Header Injection Detection

The Header Injection detector focuses on identifying:

1. **CR/LF sequences**: Detects carriage return and line feed character combinations that could split HTTP headers and insert unauthorized headers.

2. **URL-encoded CR/LF**: Identifies URL-encoded variants (`%0d`, `%0a`, `%0d%0a`) that might bypass input filters.

3. **Header name insertion**: Recognizes attempts to inject common HTTP header names like `Set-Cookie`, `Location`, or security headers.

4. **Session hijacking**: Specifically targets attempts to inject `Set-Cookie` headers that could hijack user sessions.

5. **Security header manipulation**: Detects injection of security-related headers like `Content-Security-Policy` that could weaken browser protections.

6. **Obfuscation techniques**: Identifies various encoding and obfuscation methods used to hide header injection attempts.

### CSV Injection Detection

The CSV Injection detector focuses on identifying:

1. **Formula markers**: Detects inputs beginning with formula markers (`=`, `+`, `-`, `@`) that could trigger formula execution when opened in spreadsheet applications.

2. **Dangerous functions**: Identifies spreadsheet functions that could lead to remote code execution, data exfiltration, or other malicious activities, such as `HYPERLINK`, `DDE`, `WEBSERVICE`, and `IMPORTXML`.

3. **Cell reference manipulation**: Recognizes attempts to reference other cells or sheets that could be used as part of a complex attack.

4. **DDE commands**: Specifically detects Dynamic Data Exchange commands that could execute system commands when a spreadsheet is opened.

5. **Obfuscation techniques**: Identifies attempts to hide formula injections using concatenation, CHAR() functions, and other obfuscation methods.

6. **Cross-application targets**: Covers formula patterns for multiple spreadsheet applications, including Microsoft Excel, LibreOffice Calc, and Google Sheets.

### Regular Expression DoS (ReDoS) Detection

The ReDoS detector focuses on identifying:

1. **Character repetition**: Detects long repetitions of the same character that might trigger excessive backtracking in regex engines.

2. **Nested repetition**: Identifies nested repetition patterns like `(a+)+b` that are known to cause exponential backtracking.

3. **Alternation with repetition**: Recognizes patterns like `(a|b|c)+` that might lead to excessive branching during matching.

4. **Complex nested groups**: Detects multiple levels of nested groups with quantifiers that can lead to catastrophic backtracking.

5. **Suspicious input patterns**: Identifies input with abnormally low character diversity, extremely long inputs, or inputs with structures known to challenge regex engines.

6. **Heuristic analysis**: Uses compression ratio and character diversity metrics to identify potentially problematic input that might not match specific patterns.

### NoSQL Injection Detection

The NoSQL Injection detector focuses on identifying:

1. **MongoDB operator abuse**: Detects the use of MongoDB operators like `$gt`, `$ne`, `$exists`, `$where`, etc., that could be used to manipulate query behavior and bypass authentication or access controls.

2. **JavaScript execution**: Identifies attempts to execute arbitrary JavaScript code via the `$where` operator or function definitions that could lead to server-side JavaScript execution.

3. **Query structure manipulation**: Recognizes attempts to modify the query structure by injecting operators or manipulating JSON objects to alter query behavior.

4. **Authentication bypass techniques**: Specifically targets common patterns used to bypass login systems, such as the use of `$ne` operators with empty strings or null values.

5. **Tautology attacks**: Detects conditions that are always true, which could be used to bypass filters or access all records in a collection.

6. **Field/property access manipulation**: Identifies attempts to access or modify database fields using bracket notation or other specialized syntax.

### Log Injection/Log Forging Detection

The Log Injection detector focuses on identifying:

1. **Newline manipulation**: Detects various forms of newline characters (CR, LF, CRLF) in raw form, URL-encoded form, or escaped sequences that could be used to insert additional log entries.

2. **Log level spoofing**: Identifies attempts to insert fake log levels (INFO, ERROR, WARNING, etc.) that might make injected entries appear legitimate.

3. **Timestamp forgery**: Detects common timestamp formats that could be used to make injected logs appear to be from a different time.

4. **Event message spoofing**: Recognizes common log event messages like "user logged in," "authentication successful," or "system rebooted" that might be used to create misleading entries.

5. **Log structure manipulation**: Identifies patterns that mimic log structure markers like brackets, pipes, colons, and dashes in combinations that might indicate log injection.

6. **Control character injection**: Detects non-printable characters that could be used to manipulate how logs are displayed or processed.

7. **Logging framework imitation**: Recognizes attempts to mimic specific logging frameworks' output formats to create more convincing fake entries.

## Development

### Adding New Detectors

To add a new detector type:

1. Create a new file in the `src/detectors` directory
2. Implement the `InputDetector` trait for your new detector
3. Add an endpoint in `main.rs` that uses your detector
4. Add the module to `src/detectors/mod.rs`

### Running Tests

```bash
cargo test
```

## Deployment

The API can be deployed to Fly.io using the included GitHub Actions workflow.
