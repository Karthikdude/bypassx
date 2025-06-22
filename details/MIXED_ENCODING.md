# MIXED_ENCODING Bypass Technique

## Overview

The MIXED_ENCODING bypass technique exploits vulnerabilities in web applications that improperly handle character encoding.  It involves sending a request containing data encoded in multiple character encodings, leveraging the application's potential failure to consistently interpret the encoding to inject malicious payload, often bypassing input validation and sanitization mechanisms. This often results in successful exploitation of vulnerabilities like Cross-Site Scripting (XSS) or SQL Injection.

## Technical Details

- **Method**: HTTP Request Body and Parameters Manipulation, Character Encoding Manipulation.
- **Vulnerability**: Improper input validation and sanitization related to character encoding, inconsistent handling of multiple encodings within a single request, vulnerabilities in character encoding converters.
- **Impact**: Arbitrary code execution (through XSS), database manipulation (through SQL injection), data exfiltration, unauthorized access, and denial of service.
- **Common Targets**: Web applications that process user-supplied data (e.g., forms, search boxes), applications lacking robust input validation and sanitization, applications that incorrectly handle multi-byte character encoding conversions.

## Example

Let's assume a vulnerable web application with a search functionality. A simple search for `' OR '1'='1` might be blocked. However, by using mixed encoding, we can bypass this.

We can encode the payload `' OR '1'='1` in UTF-8 and then wrap it inside a different encoding, such as ISO-8859-1.  This obfuscates the payload, making it harder for simple input validation rules to detect.

**Example Payload (Illustrative):**

Assume the application expects data in ISO-8859-1.  A malicious payload in UTF-8 might look like this:
`%E2%80%99%20OR%20%E2%80%991%E2%80%99%3D%E2%80%991` which is UTF-8 encoding of `' OR '1'='1`

A browser or application might misinterpret this UTF-8 encoded payload assuming it's ISO-8859-1, thus leading to the SQL injection. This precise behavior depends on the vulnerable application's encoding handling.


## How to Test

### Using curl

This example assumes a vulnerable search endpoint at `/search?q=`.  Replace this with the actual URL.

```bash
curl "http://vulnerable-app/search?q=%E2%80%99%20OR%20%E2%80%991%E2%80%99%3D%E2%80%991" -H "Content-Type: application/x-www-form-urlencoded; charset=ISO-8859-1"
```

This command sends the UTF-8 encoded payload while specifying ISO-8859-1 in the header, creating the mixed encoding scenario. Adapt this command with different encodings and payloads as needed.

### Using Burp Suite

1. Intercept the request to the vulnerable endpoint.
2. Go to the "Raw" tab and modify the request body/parameters.
3. Manually encode part of the payload using UTF-8 or other encodings (use Burp Suite's encoder).
4. Ensure the specified charset in the headers (if any) is different from the encoding of your payload.
5. Forward the modified request. Observe the application's response for any unusual behavior.


### Manual Testing

1. Use your browser's developer tools (usually F12) to inspect the HTTP requests.
2. Modify the request parameters, encoding part of the input using different encodings (e.g., URL encoding part of it and leaving another part in its original encoding).
3. Observe the application's response to see if the mixed encoding bypasses any security measures.


## Security Implications

- **Bypasses input validation:** This technique can bypass input validation rules that only check for specific character sets or encodings.
- **Circumvents sanitization:** It can bypass sanitization functions that do not handle multiple encodings properly.
- **Facilitates XSS and SQLi:**  It leads to successful XSS and SQL injection attacks.
- **Escalation of privileges:**  Successful exploitation might lead to privilege escalation and full server compromise.

Real-world scenarios include attackers injecting malicious JavaScript code through XSS or manipulating database queries through SQL injection by leveraging inconsistent character encoding handling.


## Recommendations for Defenders

- **Consistent Encoding:**  Establish a single, consistent character encoding (e.g., UTF-8) for all input and output.
- **Strict Input Validation:** Implement robust input validation and sanitization that's independent of encoding.  Use parameterized queries (prepared statements) to prevent SQL injection.
- **Encoding Detection and Normalization:** Detect the encoding of incoming data and normalize it to the chosen encoding before processing.  Use libraries that handle encoding conversions safely.
- **Output Encoding:** Properly encode output based on the context (HTML encoding for HTML output, URL encoding for URLs).
- **WAF Rules:** Configure your Web Application Firewall (WAF) to detect and block requests with suspicious encoding patterns or inconsistencies.
- **Secure Coding Practices:** Follow secure coding principles and use appropriate escaping and encoding mechanisms for different data contexts.


## Related Techniques

- Unicode Character Bypass
- Double Encoding Bypass
- URL Encoding Bypass


## References

- OWASP Top Ten:  (Relevant sections on XSS, SQL injection, and input validation)
- CWE (Common Weakness Enumeration):  (Search for CWE IDs related to encoding vulnerabilities)
-  Various blog posts and security advisories on specific vulnerabilities related to character encoding (search for "mixed encoding bypass" or similar terms).


**Note:** This documentation provides general information.  The effectiveness of MIXED_ENCODING will vary depending on the specific vulnerabilities present in the targeted application.  Always obtain explicit permission before testing vulnerabilities on systems you do not own.
