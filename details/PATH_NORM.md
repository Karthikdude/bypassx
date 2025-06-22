# PATH_NORM Bypass Technique

## Overview

PATH_NORM is a bypass technique that leverages the inconsistent handling of path normalization across different web servers and applications. It exploits the way applications resolve and interpret directory traversal attempts, often resulting in unexpected file access or directory listing. This technique manipulates the path component of a URL or file request to exploit weaknesses in path canonicalization (the process of converting a path into its standard form). By injecting carefully crafted sequences of "." (dots) and ".." (double dots), an attacker can potentially bypass security restrictions intended to prevent directory traversal.  It's crucial to note that this relies on *inconsistent* handling; a perfectly implemented system will correctly reject such attempts.


## Technical Details

- **Method**: URL Manipulation
- **Vulnerability**: Inconsistent or improper path canonicalization, improper input validation (lack of strong path sanitization).  The core issue lies in how the application handles relative paths and their resolution to absolute paths.
- **Impact**: Unauthorized file access (reading sensitive files like configuration files, source code, or user data), directory listing disclosure, potentially leading to further exploitation (e.g., remote code execution if the server executes files in accessible directories).
- **Common Targets**: Web applications with flawed file upload functionalities, applications handling file downloads, custom CMS or frameworks with weak file path validation.


## Example

Let's assume a vulnerable application accesses files via a URL like `/files/download.php?file=filename.txt`.  A simple directory traversal attack might try `/files/download.php?file=../../etc/passwd`.  However, many systems are protected against this. PATH_NORM tries to bypass such protection by using variations:

`/files/download.php?file=././././././././././././etc/passwd` (Multiple "." characters)
`/files/download.php?file=../%2e%2e/etc/passwd` (Using URL-encoded ".." -  `%2e` is the URL encoding of ".")
`/files/download.php?file=a/b/c/../../../../etc/passwd` (a combination of forward and backward traversal).

The attacker aims to find a sequence that confuses the server's path normalization process, leading to the traversal.


## How to Test

### Using curl

```bash
curl "http://target.com/files/download.php?file=././././././etc/passwd"
curl "http://target.com/files/download.php?file=../%2e%2e/etc/passwd"
curl "http://target.com/files/download.php?file=a/b/c/../../../../etc/passwd"
```

Replace `http://target.com/files/download.php?file=` with the actual vulnerable URL.  Experiment with different variations of dots and double dots, potentially using URL encoding.

### Using Burp Suite

1. **Proxy Intercept:** Set your browser to use Burp Suite as a proxy.
2. **Make Request:** Access the vulnerable file download functionality in your browser.
3. **Intercept Request:** Intercept the HTTP request in Burp Suite's Proxy history.
4. **Modify Request:**  Edit the `file` parameter in the request, replacing the filename with the PATH_NORM variations shown in the "Example" section.  Experiment with multiple variations.
5. **Forward Request:** Forward the modified request to the server.
6. **Analyze Response:** Check the response for any sensitive information revealed by the bypass.

### Manual Testing

Manually construct the malicious URLs using the variations from the example and enter them into your browser's address bar.  Observe the browser's response for signs of successful traversal.


## Security Implications

- **Bypasses security controls:** PATH_NORM bypasses input validation that only checks for explicit occurrences of ".." or only limits the depth of path traversal.
- **Data breaches:**  Sensitive files containing sensitive information (credentials, source code, private data) could be exposed.
- **Remote Code Execution (RCE):** In some cases, successful traversal to an executable file could allow attackers to execute arbitrary code on the server.
- **Denial of Service (DoS):**  Repeated attempts to traverse directories can cause a DoS situation if not properly handled by the server.


## Recommendations for Defenders

- **Robust input validation:** Implement strict input validation and sanitization for all file paths received from user input. Use a whitelist approach specifying allowed characters and directory structures.
- **Path canonicalization:** Use a secure path canonicalization library that handles various path traversal techniques reliably. Always resolve paths to their absolute form and check against an allowed path whitelist.
- **Secure coding practices:** Avoid directly using user-supplied input in file system operations. Always validate and sanitize inputs before interacting with the file system.
- **WAF/security tool configurations:** Configure your Web Application Firewall (WAF) to detect and block requests containing patterns indicative of PATH_NORM attacks (e.g., multiple "." or ".." characters within file paths).
- **Regular security audits and penetration testing:** Regularly audit your web applications for vulnerabilities, including directory traversal flaws. Conduct penetration tests to identify potential bypasses.


## Related Techniques

- Directory Traversal (classic techniques)
- URL Manipulation
- HTTP Parameter Pollution


## References

- OWASP Top 10: A1 - Injection
- [Various blog posts on path traversal and bypass techniques](Search for "path traversal bypass techniques" on your favorite search engine)
- [Relevant CVEs](Search for relevant CVEs on the NVD website) – many CVEs relate to weak implementations vulnerable to path traversal, but no single CVE is specifically named "PATH_NORM" as it's a generic description of a class of bypasses.
