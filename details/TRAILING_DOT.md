# TRAILING_DOT Bypass Technique

## Overview

The TRAILING_DOT bypass technique exploits weaknesses in input validation routines that fail to properly handle trailing dots (`.`) in user-supplied input.  This can lead to bypassing security filters designed to block or sanitize malicious input, such as file path traversal attempts or SQL injection payloads.  The trailing dot is often ignored or stripped off during superficial validation, effectively allowing an attacker to append malicious characters after the dot, which are then processed without proper filtering.

## Technical Details

- **Method**: Input Manipulation, URL Manipulation, Parameter Tampering
- **Vulnerability**: Insufficient Input Validation, lack of robust file path sanitization, improper handling of parameter values.
- **Impact**: File path traversal, directory listing, arbitrary file access, SQL injection (if combined with other techniques), potentially Remote Code Execution (RCE) depending on the application's architecture and back-end logic.
- **Common Targets**: Web applications that handle file uploads, user-provided file paths, dynamic URL generation based on user input, applications with weak input sanitization mechanisms in their backend logic.


## Example

Let's assume a vulnerable file upload script expects a file named `image.jpg`.  A typical validation might check for the `.jpg` extension.  An attacker could bypass this by uploading a file named `image.jpg.php`.  The trailing dot and the `.php` extension might be ignored, leading to the server processing the file as a PHP script, potentially executing malicious code.  A similar scenario applies to path traversal, where `/etc/passwd.` could be used to bypass checks for `/etc/passwd` alone.

## How to Test

### Using curl

```bash
curl "http://vulnerable-site.com/upload?file=image.jpg.php" -F "file=@malicious_file.php"
```
This example attempts to upload a file named `malicious_file.php` while using the manipulated filename `image.jpg.php` in the URL parameter.  Replace `"http://vulnerable-site.com/upload?file=image.jpg.php"` and `@malicious_file.php` with your target URL and malicious file path respectively.

### Using Burp Suite

1. Send a request to the vulnerable web application (e.g., a file upload or a request that handles user-supplied filenames).
2. Intercept the request in Burp Suite's proxy.
3. Modify the parameter containing the filename (e.g., `filename=image.jpg`) by adding a trailing dot followed by a malicious extension: `filename=image.jpg.php`.
4. Forward the modified request to the application.
5. Observe the application's response.  A successful bypass will indicate that the malicious file is processed or that unexpected behavior occurs.


### Manual Testing

1. Access a webpage with user-supplied input fields affecting filenames or file paths.
2. Enter a filename with a trailing dot and an unexpected extension (e.g., `image.jpg.php`, `mydocument.txt.exe`).
3. Submit the form or request.
4. Observe the application's response.  Successful bypass could reveal unexpected file access or execution.


## Security Implications

- **Bypasses input validation:** This technique bypasses superficial input validation that only checks for the primary file extension without considering trailing dots.
- **Potential for RCE:** In combination with other vulnerabilities, it can lead to Remote Code Execution (RCE) if the uploaded file is processed by an interpreter.
- **Data breaches:**  If the vulnerability is related to file access, sensitive data can be compromised.
- **Denial of Service (DoS):**  While less common, in some scenarios, a trailing dot could cause unexpected behavior leading to service disruptions.


## Recommendations for Defenders

- **Robust Input Validation:**  Implement rigorous input validation that checks not only for extensions but also for the presence of unexpected characters, especially dots within filenames or paths.  Use regular expressions to validate file names against allowed patterns.
- **Whitelist Approach:**  Instead of blacklisting disallowed characters or extensions, adopt a whitelist approach, only accepting specifically allowed filenames and extensions.
- **File Path Sanitization:** Thoroughly sanitize user-supplied file paths before using them in any file system operations.  Avoid direct concatenation of user input with fixed paths.
- **Content-Type Validation:** Verify the Content-Type header of uploaded files to ensure it matches the expected file type.
- **WAF/Security Tool Configurations:** Configure your Web Application Firewall (WAF) or other security tools to detect and block requests containing suspicious patterns, such as multiple dots or unexpected extensions after a primary extension.
- **Secure Coding Practices:** Follow secure coding principles to prevent vulnerabilities related to file handling, input validation, and path manipulation.


## Related Techniques

- Directory Traversal
- Null Byte Injection
- Extension Manipulation
- Path Traversal

## References

- OWASP Top 10: A1-Injection
- OWASP Testing Guide: File Upload Vulnerabilities
- Various blog posts and articles on file upload vulnerabilities (search for "file upload bypass techniques").  (Note: Specific links omitted as dynamically generated content changes rapidly)
