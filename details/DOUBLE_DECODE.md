# DOUBLE_DECODE Bypass Technique

## Overview

The DOUBLE_DECODE bypass technique exploits the improper handling of encoded data by web applications.  It leverages the fact that some applications might only decode user-supplied input once, leaving a second layer of encoding intact. By double-encoding a malicious payload, an attacker can bypass input validation or sanitization mechanisms designed to prevent code injection or cross-site scripting (XSS) attacks.  This technique relies on the application's failure to perform sufficient decoding steps before processing user input.

## Technical Details

- **Method**: URL Manipulation, Input Parameter Tampering
- **Vulnerability**: Insufficient input validation and sanitization, specifically failure to handle multiple layers of encoding (e.g., URL encoding, HTML encoding).
- **Impact**: Code injection (e.g., SQL injection, command injection), Cross-Site Scripting (XSS), and other types of attacks that rely on manipulating input parameters.  Successful exploitation can lead to data breaches, unauthorized access, or complete server compromise.
- **Common Targets**: Web applications that accept user input and process it without proper validation and sufficient decoding. This is particularly common in older applications or those with poorly designed input handling routines.

## Example

Let's assume a vulnerable application expects a username parameter.  A malicious payload might be `<script>alert('XSS')</script>`.  A single URL encoding would look like this: `%3Cscript%3Ealert%28'XSS'%29%3C%2Fscript%3E`.  However, if the application only decodes once, this would still be interpreted as malicious JavaScript.  Double encoding it produces: `%253Cscript%253Ealert%2528%2527XSS%2527%2529%253C%252Fscript%253E`.  The application might only decode the first `%` sequences, leaving the inner encoding intact and still resulting in the execution of malicious JavaScript.

## How to Test

### Using curl

```bash
curl "http://vulnerable-app.com/profile?username=%253Cscript%253Ealert%2528%2527XSS%2527%2529%253C%252Fscript%253E"
```
This command uses `curl` to send a request with a double-URL-encoded XSS payload.  Replace `http://vulnerable-app.com/profile` with the actual URL of the vulnerable application.

### Using Burp Suite

1. Intercept the request to the vulnerable application using Burp Suite's proxy.
2. Modify the username parameter value to include a double-encoded payload (e.g., `%253Cscript%253Ealert%2528%2527XSS%2527%2529%253C%252Fscript%253E`).
3. Forward the modified request.
4. Observe the application's response. If the payload executes, it confirms the vulnerability.  Try with different encoding types (URL, HTML, etc.) and combinations.

### Manual Testing

1. Access the vulnerable web application.
2. Identify a parameter that accepts user input (e.g., username, search query).
3. Manually encode a malicious payload twice (using a URL encoder or similar tool).
4. Submit the double-encoded payload through the identified input parameter.
5. Observe the application's response.  Successful execution of the payload indicates a vulnerability.


## Security Implications

- **Bypasses:** This technique bypasses input validation and sanitization filters that only perform single-level decoding. It can defeat security mechanisms relying on simple encoding checks.
- **Potential Risks and Impacts:**  Successful exploitation can lead to XSS, SQL injection, command injection, data breaches, account takeover, and website defacement.
- **Real-world attack scenarios:** An attacker could inject malicious JavaScript to steal cookies, redirect users to phishing sites, or perform other harmful actions.  In the case of SQL injection, they could execute arbitrary SQL commands against the database.


## Recommendations for Defenders

- **Detect:** Implement robust input validation and sanitization mechanisms that handle multiple layers of encoding.  Regularly scan for vulnerabilities using automated tools.  Monitor logs for suspicious activity, including unusual encodings in input parameters.
- **Mitigation Strategies:**  Always decode input parameters multiple times, ensuring complete decoding before further processing.  Use parameterized queries to prevent SQL injection vulnerabilities. Employ output encoding to prevent XSS attacks.
- **Secure Coding Practices:**  Follow secure coding guidelines (OWASP, SANS).  Use appropriate encoding and decoding functions according to the context.  Sanitize all user inputs before using them in any dynamic code or database queries.
- **WAF/Security tool configurations:** Configure your Web Application Firewall (WAF) to detect and block multiple layers of encoding in suspicious requests.


## Related Techniques

- URL Encoding
- HTML Encoding
- Unicode Encoding
- Multi-stage encoding
- Parameter pollution

## References

- OWASP Top 10
- OWASP XSS Prevention Cheat Sheet
- [Relevant CVE entries (search for "double encoding bypass")] (e.g., search on the NVD website)


**(Note:  Replace bracketed placeholders with specific CVE numbers and relevant links as needed.)**
