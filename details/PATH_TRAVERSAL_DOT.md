# PATH_TRAVERSAL_DOT Bypass Technique

## Overview

The PATH_TRAVERSAL_DOT technique is a path traversal bypass method that leverages the repeated use of the dot (`.`) character to navigate directory structures.  Unlike typical path traversal attacks that use `../` to move up directories, this technique uses multiple dots to potentially confuse or circumvent input sanitization mechanisms that only explicitly check for `../` or variations like `%2e%2e`.  This makes it a more subtle and harder-to-detect path traversal attempt.

## Technical Details

- **Method**: URL Manipulation
- **Vulnerability**: Path Traversal vulnerability.  This exploits insufficient input validation and sanitization of user-supplied data in file paths.
- **Impact**:  Unauthorized access to files and directories outside the web application's intended directory structure, including sensitive configuration files, source code, system files, and potentially data exfiltration.
- **Common Targets**: Web applications that handle file uploads, downloads, or user-provided file paths without proper validation.


## Example

Let's assume a vulnerable application allows users to download files using a parameter like `/download?file=filename`.  A typical path traversal might be `/download?file=../../etc/passwd`.  However, a PATH_TRAVERSAL_DOT attack might try:

`/download?file=././././././././etc/passwd`

This uses multiple `./` sequences to effectively move up the directory structure, eventually reaching `/etc/passwd`. The number of dots required depends on the directory depth and the effectiveness of the input validation.

## How to Test

### Using curl

```bash
curl "http://vulnerable-app.com/download?file=./././././etc/passwd"
```
(Replace `vulnerable-app.com` and the path with the actual target and file)

### Using Burp Suite

1. Identify a vulnerable endpoint (e.g., a file download function) in Burp's Proxy history.
2. Right-click the request and send it to the Repeater.
3. Modify the file parameter in the request, adding multiple `./` sequences before the target file path.  For example, change `file=myfile.txt` to `file=./././././myfile.txt` and then `file=././././././././etc/passwd` (testing different levels of depth).
4. Forward the modified request and analyze the response. A successful attack will return the contents of the target file.

### Manual Testing

1. Identify a file download or similar endpoint.
2. Try constructing URLs with increasing numbers of `./` prefixes to the intended target file or directory. Example: `/download?file=./myfile.txt`, `/download?file=././myfile.txt`, `/download?file=./././myfile.txt`, etc.
3. Observe the application's response.  Unexpected file downloads or error messages related to unauthorized access indicate a vulnerability.


## Security Implications

- **Bypasses:** This bypasses input validation rules that specifically look for `../` sequences.
- **Potential Risks:** Data breaches, system compromise, unauthorized access to sensitive information.
- **Real-world Attack Scenarios:** An attacker could use this technique to steal credentials from password files, access sensitive configuration data, or download arbitrary files from the server.


## Recommendations for Defenders

- **Detection:** Implement robust input validation and sanitization, checking not just for `../` but also for multiple `.` characters and potential variations like `%2e` (URL-encoded dot).  Use a Web Application Firewall (WAF) with rules to detect and block path traversal attempts.
- **Mitigation Strategies:**  Use a whitelist approach, specifying allowed file paths explicitly, rather than relying on blacklisting disallowed characters or sequences. Validate and sanitize all user-supplied input related to file paths.  Employ proper file system permissions to restrict access.
- **Secure Coding Practices:**  Avoid constructing file paths based solely on user input. Use safe library functions that handle path manipulation securely.
- **WAF/security tool configurations:** Configure your WAF to detect and block requests containing excessive numbers of dots (`./`) in file paths. Implement intrusion detection and prevention systems (IDS/IPS) to monitor for suspicious file access attempts.


## Related Techniques

- PATH_TRAVERSAL_DOUBLE_DOT (`../`)
- PATH_TRAVERSAL_NULL_BYTE
- PATH_TRAVERSAL_ENCODED
- Directory Indexing


## References

- OWASP Top 10: A03:2021-Sensitive Data Exposure
- OWASP Testing Guide: Path Traversal
- Various security blog posts on path traversal bypass techniques (search for "path traversal bypass techniques").  (Note: Specific links to blog posts are omitted due to their constantly changing nature)
- (Add any relevant CVE numbers here if applicable)
