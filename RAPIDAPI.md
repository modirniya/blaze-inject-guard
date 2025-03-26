# Blaze Inject Guard API

A comprehensive API for detecting various types of injection attacks and malicious inputs in your applications.

## API Description
Blaze Inject Guard is a powerful security API that helps developers detect and prevent various types of injection attacks. It provides both individual endpoint testing for specific injection types and comprehensive scanning capabilities for multiple attack vectors simultaneously.

## Features
- 12 Different Injection Detection Types
- Comprehensive Scanning
- Batch Processing Support
- Real-time Detection
- High Performance
- Easy Integration
- Detailed Response Format

## Available Endpoints

### 1. Health Check
```http
GET /health
```
Check if the API is running and healthy.

**Response Example:**
```json
{
    "status": "healthy",
    "timestamp": "2024-03-25T21:10:45Z"
}
```

### 2. Version Check
```http
GET /version
```
Get the current version of the API.

**Response Example:**
```json
{
    "version": "0.1.0"
}
```

### 3. Individual Injection Detection
```http
POST /detect/{type}
```
Where `{type}` can be:
- command
- xss
- ldap
- xml
- template
- html
- path
- header
- csv
- redos
- nosql
- log

**Request Body:**
```json
{
    "content": "string to test"
}
```

**Response Example:**
```json
{
    "is_malicious": true,
    "detector_type": "command_injection"
}
```

### 4. Comprehensive Detection
```http
POST /detect/comprehensive
```
Test for all types of injections in a single request.

**Request Body:**
```json
{
    "content": "string to test"
}
```

**Response Example:**
```json
{
    "command_injection": false,
    "xss": true,
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
    "is_safe": false
}
```

### 5. Batch Detection
```http
POST /detect/batch
```
Test multiple inputs with selective detection types.

**Request Body:**
```json
{
    "contents": [
        "first string to test",
        "second string to test"
    ],
    "detectors": {
        "command_injection": true,
        "xss": true,
        "ldap_injection": false,
        "xml_injection": true,
        "template_injection": false,
        "html_injection": true,
        "path_traversal": true,
        "header_injection": false,
        "csv_injection": false,
        "redos": true,
        "nosql_injection": false,
        "log_injection": true
    }
}
```

**Response Example:**
```json
{
    "results": [
        {
            "content": "first string to test",
            "detections": {
                "command_injection": false,
                "xss": false,
                "xml_injection": false,
                "html_injection": false,
                "path_traversal": false,
                "redos": false,
                "log_injection": false
            },
            "is_safe": true
        },
        {
            "content": "second string to test",
            "detections": {
                "command_injection": false,
                "xss": false,
                "xml_injection": false,
                "html_injection": false,
                "path_traversal": false,
                "redos": false,
                "log_injection": false
            },
            "is_safe": true
        }
    ]
}
```

## Use Cases
1. **Web Application Security:**
   - Validate user inputs
   - Protect form submissions
   - Secure API endpoints

2. **Content Management Systems:**
   - Validate user-generated content
   - Protect against malicious uploads
   - Secure comment systems

3. **DevSecOps:**
   - Integrate with CI/CD pipelines
   - Automated security testing
   - Quality assurance checks

4. **Data Processing:**
   - Validate data imports
   - Secure file processing
   - Database input validation

## Pricing Tiers
1. **Free Tier**
   - 100 requests per day
   - Access to individual detection endpoints
   - Basic rate limiting

2. **Basic Tier**
   - 1,000 requests per day
   - Access to all endpoints
   - Standard rate limiting
   - Email support

3. **Professional Tier**
   - 10,000 requests per day
   - Access to all endpoints
   - Priority rate limiting
   - Priority email support
   - Batch processing

4. **Enterprise Tier**
   - Custom request limits
   - Custom rate limiting
   - Dedicated support
   - Custom integration support
   - SLA guarantee

## Code Examples

### Python
```python
import requests
import json

api_url = "https://blaze-inject-guard.p.rapidapi.com"
headers = {
    'Content-Type': 'application/json',
    'X-RapidAPI-Key': 'your-api-key',
    'X-RapidAPI-Host': 'blaze-inject-guard.p.rapidapi.com'
}

# Test for XSS
response = requests.post(
    f"{api_url}/detect/xss",
    headers=headers,
    json={"content": "<script>alert('test')</script>"}
)
print(response.json())
```

### Node.js
```javascript
const axios = require('axios');

const options = {
    method: 'POST',
    url: 'https://blaze-inject-guard.p.rapidapi.com/detect/comprehensive',
    headers: {
        'Content-Type': 'application/json',
        'X-RapidAPI-Key': 'your-api-key',
        'X-RapidAPI-Host': 'blaze-inject-guard.p.rapidapi.com'
    },
    data: {
        content: 'string to test'
    }
};

axios.request(options)
    .then(response => console.log(response.data))
    .catch(error => console.error(error));
```

### PHP
```php
<?php
$curl = curl_init();

curl_setopt_array($curl, [
    CURLOPT_URL => "https://blaze-inject-guard.p.rapidapi.com/detect/batch",
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_ENCODING => "",
    CURLOPT_MAXREDIRS => 10,
    CURLOPT_TIMEOUT => 30,
    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
    CURLOPT_CUSTOMREQUEST => "POST",
    CURLOPT_POSTFIELDS => json_encode([
        'contents' => ['test string 1', 'test string 2'],
        'detectors' => [
            'command_injection' => true,
            'xss' => true
        ]
    ]),
    CURLOPT_HTTPHEADER => [
        "X-RapidAPI-Host: blaze-inject-guard.p.rapidapi.com",
        "X-RapidAPI-Key: your-api-key",
        "Content-Type: application/json"
    ],
]);

$response = curl_exec($curl);
$err = curl_error($curl);

curl_close($curl);

if ($err) {
    echo "cURL Error #:" . $err;
} else {
    echo $response;
}
?>
```

## Support
For any questions or issues, please contact our support team at support@blazeinjectguard.com

## FAQ
1. **What types of injection attacks can this API detect?**
   - The API can detect 12 different types of injection attacks including command injection, XSS, LDAP injection, and more.

2. **How accurate is the detection?**
   - Our API has been tested extensively with a 99.9% accuracy rate on known attack patterns.

3. **Is there a rate limit?**
   - Yes, rate limits vary by pricing tier. See the Pricing section for details.

4. **Can I test multiple inputs at once?**
   - Yes, you can use the batch endpoint to test multiple inputs simultaneously.

5. **Do you offer custom solutions?**
   - Yes, enterprise customers can request custom integrations and features.

## Terms of Service
By using this API, you agree to:
1. Not use the API for malicious purposes
2. Respect rate limits
3. Not share your API key
4. Report any security vulnerabilities
5. Comply with all applicable laws and regulations

## Privacy Policy
We collect:
1. API usage statistics
2. Error logs
3. Request metadata

We do not:
1. Store your input data
2. Share your usage data
3. Track individual users 