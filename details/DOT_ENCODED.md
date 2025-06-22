# DOT_ENCODED Bypass Technique

## Overview

The DOT_ENCODED bypass technique leverages the encoding of dots (`.`) within a URL or other input fields to circumvent input validation filters that might be designed to block certain characters or patterns.  Many web applications and security solutions perform incomplete or inconsistent validation, allowing encoded dots to slip through and potentially lead to unexpected behavior or vulnerabilities like path traversal.  This technique relies on the fact that some systems might interpret multiple encoded dots (e.g., `%2E%2E%2E`) differently than a single literal dot (`.`).


## Technical Details

- **Method**: URL Manipulation, Input Encoding
- **Vulnerability**: Insufficient Input Sanitization, Inconsistent Encoding Handling, Path Traversal vulnerabilities (in some cases)
- **Impact**:  Potential for unauthorized file access, directory traversal, data exfiltration, or even arbitrary code execution if combined with other vulnerabilities.  In less severe cases, it might lead to unexpected application behavior or error messages revealing sensitive information.
- **Common Targets**: Web applications with insufficient input validation on file paths, URLs, or other user-supplied inputs.


## Example

Let's assume a vulnerable application expects a filename like `image.jpg`.  A simple input filter might check for the extension `.jpg` but fail to properly handle encoded dots.

**Vulnerable Request:**  `/images/image.jpg`

**Bypass Request (DOT_ENCODED):** `/images/image%2E%2E%2Ejpg`  (This encodes the `.` as `%2E` multiple times)

The application might interpret `%2E%2E%2E` as three dots, potentially allowing access to files outside the intended directory, depending on the server's handling of the encoded characters.  For example, on a system with path traversal vulnerability this could allow to access `../etc/passwd` if the `%2E%2E` sequences are interpreted as directory traversal operators.

## How to Test

### Using curl

```bash
curl "http://target.com/images/image%2E%2E%2Ejpg"
```

Replace `http://target.com/images/image.jpg` with the actual URL you are testing.  Experiment with different numbers of encoded dots (`%2E%2E`, `%2E%2E%2E`, `%2E%2E%2E%2E`, etc.) to see if the application's behavior changes.

### Using Burp Suite

1. Intercept a request to a vulnerable endpoint.
2. Go to the "Repeater" tab in Burp Suite.
3. Paste the request.
4. Modify the request by encoding dots in the URL parameter or filename as `%2E`.
5. Try multiple combinations of encoded dots.
6. Observe the application's response for changes in behavior or access to unauthorized resources.

### Manual Testing

1. Access a vulnerable endpoint in your browser.
2. Manually modify the URL by URL-encoding dots in file paths or parameters. For example, change `/path/to/file.txt` to `/path/to/file%2Etxt`.
3. Observe the application response carefully.


## Security Implications

- **Bypasses:** Input validation filters that only check for literal dots or don't handle multiple encodings consistently.
- **Potential Risks:** Unauthorized file access (path traversal), information disclosure, and potentially even code execution (if combined with other vulnerabilities).
- **Real-world attack scenarios:**  An attacker could use this technique to access sensitive configuration files, steal data, or even gain remote code execution.


## Recommendations for Defenders

- **Detect:** Implement robust input validation and sanitization, specifically for file paths, URLs, and other user-supplied inputs.  Don't rely solely on client-side validation.
- **Mitigation:**  Use a consistent and thorough input validation mechanism.  Decode encoded characters *before* validation.  Employ a secure encoding scheme and avoid relying solely on percent-encoding.  Restrict access to sensitive directories.
- **Secure coding practices:** Sanitize and validate all user inputs, particularly before using them in file system operations.
- **WAF/security tool configurations:** Configure your WAF to detect and block requests containing excessive or unusual use of encoded dots in potentially vulnerable contexts.


## Related Techniques

- Percent Encoding Bypass
- Double Encoding
- Unicode Encoding Bypass
- Path Traversal


## References

- OWASP Top 10 (A1: Injection)
- [Various blog posts and security advisories on path traversal vulnerabilities](Search for "path traversal" on security blogs) -  Note: Specific links are omitted as research on this specific topic is continuously evolving and linking to specific articles might be outdated quickly.


This documentation provides a general overview. The effectiveness of the DOT_ENCODED bypass technique depends on the specific implementation of the target application's input validation and security controls. Always prioritize responsible disclosure when testing vulnerabilities.
