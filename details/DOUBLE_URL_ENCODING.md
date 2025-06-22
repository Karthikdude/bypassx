# DOUBLE_URL_ENCODING Bypass Technique

## Overview

Double URL Encoding is a bypass technique used to circumvent input validation mechanisms that only perform a single URL decoding.  It works by encoding a malicious payload twice, meaning the application might decode it once, leaving the encoded payload intact for further processing, ultimately leading to successful exploitation of vulnerabilities.  This can bypass filters designed to block malicious characters or prevent injection attacks.

## Technical Details

- **Method**: URL Manipulation
- **Vulnerability**: This technique exploits vulnerabilities in applications that inadequately sanitize or validate user-supplied input, especially in URLs or forms, and only perform a single URL decoding.  It often targets vulnerabilities like Cross-Site Scripting (XSS), SQL Injection (SQLi), and Command Injection.
- **Impact**: Successful exploitation can lead to various severe consequences, including unauthorized access to sensitive data, code execution, website defacement, account takeover, and data breaches.
- **Common Targets**: Web applications with weak input validation, particularly those relying on single URL decoding to sanitize user input in parameters, query strings, or forms.


## Example

Let's consider a simple XSS vulnerability.  Suppose a vulnerable application has a parameter named `name` in its URL. A malicious payload intending to execute Javascript could be: `<script>alert(1)</script>`.

* **Single Encoding:** `%3Cscript%3Ealert%281%29%3C%2Fscript%3E` (This might be blocked by a filter)
* **Double Encoding:** `%25%3Cscript%25%3Ealert%25%281%25%29%25%3C%2Fscript%25%3E`  (This might bypass the filter)

When the server decodes this twice, it will first decode `%25` to `%`, and then decode the resulting `%3Cscript%3Ealert%281%29%3C%2Fscript%3E` to `<script>alert(1)</script>`, executing the malicious script.


## How to Test

### Using curl

```bash
curl "http://vulnerable-site.com/page?name=%25%3Cscript%25%3Ealert%25%281%25%29%25%3C%2Fscript%25%3E"
```
Replace `vulnerable-site.com/page` with the actual vulnerable URL.  This uses `curl` to send the double-encoded payload.

### Using Burp Suite

1. Intercept the request to the vulnerable URL in Burp Proxy.
2. Select the parameter you want to test (e.g., `name`).
3. Double URL encode the malicious payload using Burp's built-in encoder.  Most versions have a dedicated option for this.
4. Forward the modified request.
5. Observe the application's response to check if the double-encoded payload was successfully processed and executed.

### Manual Testing

1. Open your browser's developer tools (usually F12).
2. Construct a URL with the double-URL-encoded payload.
3. Access the URL.
4. Monitor the browser's console or network tab for any signs of the payload execution.  Javascript alerts are a clear indication of XSS.


## Security Implications

- **Bypasses input validation:** This technique bypasses basic input validation filters that only perform single URL decoding.
- **Increases attack surface:**  It expands the potential for successful exploitation of vulnerabilities.
- **Data breaches and code execution:**  Successful exploitation can lead to data breaches and arbitrary code execution, depending on the underlying vulnerability.
- **Real-world attack scenarios:** This technique is used in sophisticated attacks to exploit vulnerabilities in web applications, often in conjunction with other bypass techniques.


## Recommendations for Defenders

- **Detect:** Implement robust input validation and sanitization procedures that handle multiple URL encoding levels. Regular security testing and penetration testing are also crucial.  Look for unusual patterns in URL parameters, especially nested or excessively long encoded strings.
- **Mitigation:**  Use a secure framework or library that inherently handles input sanitization correctly.  Apply multi-layered validation: check length restrictions, data type validation, and pattern matching before processing any user input.  Prefer parameter encoding over relying on output encoding.
- **Secure coding practices:**  Avoid using user-supplied input directly in dynamic SQL queries or system commands. Always parameterize database queries.
- **WAF/security tool configurations:** Configure WAFs (Web Application Firewalls) to detect and block patterns associated with double URL encoding or unusual encoding depth.  Regularly update and fine-tune WAF rules.


## Related Techniques

- Percent-encoding
- Unicode encoding
- HTML Encoding
- Javascript encoding


## References

- OWASP XSS Prevention Cheat Sheet
- OWASP Top Ten
- Various security blogs and research papers on URL encoding bypass techniques (search for "Double URL Encoding Bypass").  Specific links are omitted as such resources are numerous and frequently updated.
- No specific tools directly implement "Double URL Encoding" as a singular function.  However, Burp Suite, OWASP ZAP, and other security testing tools provide functionalities for encoding and decoding URLs, which can be utilized to test this technique.
