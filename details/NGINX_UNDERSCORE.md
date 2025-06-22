# NGINX_UNDERSCORE Bypass Technique

## Overview

The NGINX_UNDERSCORE bypass technique exploits a potential vulnerability in how some NGINX configurations handle URL path traversal.  It leverages the fact that some poorly configured NGINX servers might not properly sanitize or escape underscores (_) in file paths, allowing attackers to potentially bypass intended access restrictions and access sensitive files or directories.  This often occurs when a developer attempts to prevent directory traversal attacks using only basic checks without considering alternative encoding methods.

## Technical Details

- **Method**: URL Manipulation
- **Vulnerability**: Improper sanitization of underscores in URL paths leading to path traversal. This is often coupled with a lack of robust directory traversal protection.
- **Impact**: Unauthorized access to sensitive files and directories, potential for data breaches, server compromise, and privilege escalation.
- **Common Targets**: Web applications using NGINX as a reverse proxy or web server with insufficiently secure path handling in their application logic or configuration.


## Example

Let's assume a vulnerable application has a directory structure like this: `/var/www/html/app/uploads/` and only allows access to files within `/uploads/`.  A developer might think preventing `/../` sequences in the URL would be enough.  However, an attacker could attempt to access `../etc/passwd` using the following:

`/app/uploads/../../../../etc/passwd` which might fail.

However, a NGINX_UNDERSCORE attack might succeed if it is not properly handled. For example:
`/app/uploads/_/../etc/passwd`

The underscore might be incorrectly interpreted, bypassing the intended protection.  This is highly dependent on the specifics of the NGINX configuration and application logic.


## How to Test

### Using curl

```bash
curl "http://target.com/app/uploads/_/../etc/passwd"
```

Replace `http://target.com` with the target URL.  This command attempts to access the `/etc/passwd` file using the NGINX_UNDERSCORE technique.  A successful attempt would return the contents of the `/etc/passwd` file.

### Using Burp Suite

1.  Send a request to a known protected resource (e.g., `/app/uploads/protected_file.txt`).
2.  In the Repeater tab of Burp Suite, modify the URL to include the underscore traversal attempt: `/app/uploads/_/../etc/passwd`.
3.  Forward the modified request.  If the attempt is successful, you'll receive the contents of the sensitive file.

### Manual Testing

1.  Attempt to access a protected resource in your browser.
2.  Modify the URL, adding `/_/../` sequences before the file path trying to reach sensitive directories like `/etc/`, `/proc/`, or other sensitive locations.  Experiment with different variations and positions of the underscore.


## Security Implications

- **Bypasses:** This technique bypasses basic input validation and directory traversal protection mechanisms that solely rely on preventing `/../` sequences.
- **Potential Risks:** Data breaches, server compromise, and privilege escalation are all potential consequences.
- **Real-world Attack Scenarios:** An attacker could access configuration files, source code, database credentials, or other sensitive data, potentially leading to a full server compromise.


## Recommendations for Defenders

- **Detection:**  Implement robust logging and monitoring to detect unusual access attempts targeting sensitive directories.  Look for patterns involving underscores combined with directory traversal attempts.
- **Mitigation Strategies:** Properly sanitize and validate all user-supplied input, including file paths.  Use strong directory traversal protection mechanisms that go beyond simply blocking `/../` sequences. Ensure that NGINX is properly configured to handle file path requests securely.
- **Secure Coding Practices:**  Use parameterized queries, avoid direct string concatenation when constructing file paths, and properly escape special characters.  Use established libraries and frameworks to handle file access safely.
- **WAF/Security Tool Configurations:** Configure your WAF to detect and block attempts to access sensitive directories through unconventional URL manipulations involving underscores. Implement a robust rule set encompassing variations of this technique.

## Related Techniques

- Directory Traversal
- Path Traversal using Null Bytes
- Path Traversal using Unicode characters
- Path Traversal using percent encoding


## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/) (A1: Injection)
- [NGINX Documentation](https://nginx.org/en/docs/) (Consult for secure configuration practices)
- (Add specific CVE references if applicable.  There isn't a single, widely recognized CVE specifically for this technique, as it is a variation of a known vulnerability.)


**Note:**  The effectiveness of the NGINX_UNDERSCORE technique depends heavily on the specific application and NGINX configuration. It's not a universally successful bypass, but it highlights the importance of comprehensive security measures beyond simple path traversal checks.  Always adopt a layered security approach to protect your web applications.
