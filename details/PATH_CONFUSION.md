# PATH_CONFUSION Bypass Technique

## Overview

Path Confusion is a web application vulnerability that occurs when the application improperly handles or validates user-supplied data within file paths or URLs.  Attackers can exploit this by manipulating the path component of a request to access unauthorized files or directories, potentially leading to information disclosure, file manipulation, or even arbitrary code execution.  The application fails to properly separate user-supplied input from the application's internal paths, allowing attackers to traverse directories or access files outside the intended scope.


## Technical Details

- **Method**: URL Manipulation
- **Vulnerability**: Improper Input Validation, Lack of Path Canonicalization, Directory Traversal
- **Impact**: Information Disclosure (e.g., source code, configuration files), File Manipulation (e.g., deletion, modification), Arbitrary Code Execution (in severe cases), Denial of Service (DoS)
- **Common Targets**: Web applications that dynamically generate file paths based on user input, applications using file upload functionalities without proper sanitization, applications with predictable file naming conventions.


## Example

Let's assume a vulnerable application serves images from a directory `/images/`. A legitimate request might be `/images/myimage.jpg`.  A path confusion attack might look like this:

`/images/../../etc/passwd`

This attempts to traverse two directories up (`../..`) from `/images/` and then access the `/etc/passwd` file, which contains system user information. If the application doesn't properly validate or sanitize the path, it might inadvertently serve the contents of `/etc/passwd`.


## How to Test

### Using curl

```bash
curl "http://vulnerable-website.com/images/../../etc/passwd"
```

This command attempts to access the `/etc/passwd` file using the path traversal technique.  Replace `http://vulnerable-website.com/images/` with the actual URL of the vulnerable application and adjust the path traversal accordingly.

### Using Burp Suite

1. **Proxy:** Configure your browser to use Burp Suite as a proxy.
2. **Intercept:** Make a request to a file that you expect to be served from the application.
3. **Modify:** In the Burp Suite request editor, modify the path component of the URL to include `../` sequences, attempting to access files outside the intended directory. For example, change `/images/myimage.jpg` to `/images/../../etc/passwd` or similar paths to test for vulnerabilities.
4. **Forward:** Forward the modified request.
5. **Analyze:** Observe the response. If you receive unexpected content (e.g., configuration files, system files) or error messages revealing the file system structure, it indicates a potential path confusion vulnerability.

### Manual Testing

1. **Identify potential entry points:** Look for forms or parameters that accept file paths or filenames as input.
2. **Construct malicious requests:** Manually enter paths containing `../` sequences into the input fields. Start with paths that try to access directories one or two levels above the expected directory, gradually going deeper to test for vulnerabilities.
3. **Observe the results:** Check the application's response.  Unexpected file content, error messages that reveal the file system structure, or different behavior than expected indicates vulnerability.


## Security Implications

- **Bypasses:** This technique bypasses input validation and authorization controls designed to protect sensitive files and directories.
- **Risks:** Information disclosure, data breaches, server compromise (in severe cases).
- **Real-world scenarios:** Attackers might use this to steal sensitive configuration files, source code, database credentials, or escalate privileges.


## Recommendations for Defenders

- **Input Validation:** Strictly validate and sanitize all user-supplied data used in file paths.  Never trust user input.
- **Path Canonicalization:** Use library functions to normalize file paths, ensuring that `../` sequences are handled correctly and that the path always resolves to an intended location.
- **Restrict Access:** Limit access to sensitive directories and files using appropriate operating system permissions and web server configurations.
- **Secure Coding Practices:** Follow secure coding guidelines and avoid hardcoding paths. Use relative paths appropriately.
- **WAF/Security Tool Configurations:** Configure your WAF or security tools to detect and block requests containing path traversal attempts (`../`, `..\..\`, etc.).


## Related Techniques

- Directory Traversal
- File Inclusion Vulnerabilities (LFI/RFI)
- Command Injection


## References

- OWASP Top 10: A1: Injection
- Various CVE entries related to path traversal vulnerabilities (search for "path traversal" on the NVD website)


