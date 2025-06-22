# TRAILING_SEMICOLON_SLASH Bypass Technique

## Overview

The TRAILING_SEMICOLON_SLASH bypass technique exploits weaknesses in web application input sanitization by appending a semicolon followed by a slash (`;/`) to the end of a URL or parameter.  This can circumvent input validation rules designed to prevent directory traversal or file inclusion attacks. The semicolon is often misinterpreted or ignored by poorly implemented filters, allowing the trailing slash to be processed unexpectedly, potentially leading to access to restricted files or directories.

## Technical Details

- **Method**: URL Manipulation
- **Vulnerability**: Insufficient input validation, lack of proper sanitization of user-supplied input in URLs and parameters. This technique often leverages the fact that some systems might treat the semicolon as a statement separator and then evaluate the remaining part of the path, effectively bypassing filters meant to prevent path traversal.
- **Impact**: Unauthorized access to files and directories, potentially leading to data breaches, server compromise, or code execution (if vulnerable files are executable).
- **Common Targets**: Web applications with weak input validation filters in URL processing, file upload handlers, or other components dealing with user-supplied paths.  Specifically, vulnerable systems that process URLs or file paths without sufficiently robust sanitization routines.


## Example

Let's assume a vulnerable application accesses files based on a user-supplied parameter `file`.  A legitimate request might be:  `/app/view?file=document.txt`.

A TRAILING_SEMICOLON_SLASH attack would be: `/app/view?file=document.txt;/etc/passwd`.

If the application doesn't properly sanitize the `file` parameter, it might interpret the semicolon as a statement separator and proceed to try to access `/etc/passwd` after processing `document.txt`, potentially revealing sensitive system information.


## How to Test

### Using curl

```bash
curl "http://vulnerable-site.com/app/view?file=document.txt;/etc/passwd"
```

Replace `vulnerable-site.com` and `/app/view?file=document.txt` with the actual target URL and parameter.

### Using Burp Suite

1.  Send a request to the vulnerable application (e.g., `/app/view?file=document.txt`) to Burp Suite.
2.  Go to the "Repeater" tab.
3.  Modify the request by appending `; /` to the end of the `file` parameter: `/app/view?file=document.txt;/`.  Experiment with various paths.
4.  Send the modified request and observe the response.  A successful bypass will often reveal unexpected content or an error related to accessing unauthorized resources.


### Manual Testing

1.  Access the vulnerable application.
2.  Modify the URL manually in the browser's address bar by appending `; /` (or other variations) to the relevant parameter.
3.  Observe the application's response.


## Security Implications

- **Bypasses:** This technique bypasses input validation mechanisms that fail to correctly handle semicolons and slashes in the context of file paths.  It can also evade security controls that rely on simple string matching for path sanitization.
- **Potential Risks:**  Unauthorized file access, data exfiltration, system compromise, and potentially Remote Code Execution (RCE) if executable files are accessed.
- **Real-world Attack Scenarios:** An attacker could use this technique to gain access to configuration files, sensitive data, or system logs, potentially leading to further exploitation.


## Recommendations for Defenders

- **Detect:** Implement robust input validation and sanitization routines for all user-supplied input, especially in URL parameters and file paths.  Utilize regular expressions to specifically prevent the use of semicolons and slashes in unexpected contexts.  Monitor server logs for suspicious access attempts.
- **Mitigation:**  Use parameterized queries or prepared statements whenever possible to prevent injection attacks.  Escape or encode user input before using it to construct file paths.  Implement strict access control mechanisms to limit access to sensitive files and directories.  Regularly review and update your security policies and procedures.
- **Secure Coding Practices:**  Avoid using user-supplied input directly in file paths or commands. Always validate and sanitize user input before processing it.
- **WAF/Security Tool Configurations:** Configure your Web Application Firewall (WAF) to detect and block requests containing `; /` or similar patterns in URLs or parameters.  Regularly update your WAF's rules and signatures.


## Related Techniques

- Path Traversal
- Directory Traversal
- Command Injection
- Local File Inclusion (LFI)
- Remote File Inclusion (RFI)


## References

- OWASP Input Validation Cheat Sheet
- OWASP Top Ten - A1: Injection


**(Note:  No specific CVEs are directly associated with this specific technique's name, but it falls under broader categories like path traversal vulnerabilities covered by various CVEs.)**
