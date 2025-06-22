# FILE_EXT Bypass Technique

## Overview

The FILE_EXT bypass technique exploits weaknesses in file upload filters that rely solely on checking the file extension to prevent malicious file uploads.  Attackers leverage this by changing the file extension to a seemingly benign one while maintaining the actual file type's functionality. For example, an attacker might upload a malicious PHP script disguised as a `.jpg` image.  The server, trusting the extension, might save the file and execute its malicious code.

## Technical Details

- **Method**: File Manipulation, URL Manipulation (sometimes)
- **Vulnerability**: Insecure file upload handling, specifically relying only on file extension checks for validation.  This often stems from insufficient input validation or sanitization.
- **Impact**: Arbitrary code execution (most severe), Server-Side Request Forgery (SSRF), Denial of Service (DoS), Data breaches depending on the uploaded malicious payload.
- **Common Targets**: Web applications with file upload functionality, such as content management systems (CMS), forums, and custom-built applications with weak input validation.

## Example

Let's say a vulnerable web application only checks for `.jpg`, `.png`, and `.gif` extensions.  An attacker could upload a malicious PHP shell (e.g., `evil.php`) renaming it to `evil.jpg.php`.  Some poorly implemented systems might still interpret it as a PHP file if the server doesn't properly handle multiple extensions or uses the last extension to determine the file type.

## How to Test

### Using curl

```bash
curl -X POST -F "file=@evil.php;filename=evil.jpg" <target_url>
```

This command uploads `evil.php` disguised as `evil.jpg`. Replace `<target_url>` with the vulnerable file upload endpoint.  Note that `evil.php` should contain malicious code.


### Using Burp Suite

1.  **Intercept:**  Set Burp Suite to intercept HTTP requests.
2.  **Upload:** Initiate a file upload via the web application, using a legitimate file initially (e.g., a JPG image).
3.  **Modify:**  In Burp Suite's repeater or proxy, modify the request. Change the filename extension in the `Content-Disposition` header from `.jpg` to `.jpg.php` (or other malicious extension), while keeping the file contents as the malicious payload.
4.  **Forward:** Forward the modified request to the server.
5.  **Verify:** Check if the file was uploaded and if the malicious code executes.


### Manual Testing

1.  **Identify:** Locate the file upload functionality on the target website.
2.  **Prepare:** Create a malicious file (e.g., a PHP shell) and rename it with a benign extension (e.g., `.jpg`).
3.  **Upload:** Upload the renamed file through the web application.
4.  **Verify:** Attempt to execute the malicious code (e.g., accessing the uploaded file via its URL).


## Security Implications

- **Bypasses:** This bypasses input validation mechanisms relying solely on file extensions. It circumvents Content Security Policies (CSP) if the server processes the file incorrectly.
- **Potential Risks:**  Compromised server, data breaches, unauthorized access, DoS attacks, and malware distribution.
- **Real-world attack scenarios:**  Hackers could upload web shells for remote code execution, backdoors, or malware distribution. They could also upload files to exploit server-side vulnerabilities.

## Recommendations for Defenders

- **Detect:** Implement robust server-side file validation that goes beyond extension checking.  Use file magic numbers (file type signatures) for accurate identification.  Monitor server logs for suspicious file uploads and activity.
- **Mitigation:**  Use whitelist-based validation instead of blacklist-based validation.  Employ file integrity monitoring tools. Implement proper error handling and logging.
- **Secure coding practices:** Validate all user inputs rigorously.  Sanitize and escape data before using it in dynamic queries or file system operations.  Never trust user-supplied data.
- **WAF/security tool configurations:**  Configure your WAF to detect suspicious file uploads and block requests with known malicious extensions or content. Regularly update your WAF rules.


## Related Techniques

- Null Byte Injection
- Double Extension Bypass
- Directory Traversal


## References

- OWASP File Upload Cheat Sheet
- SANS Institute resources on secure coding practices.
- Various CVE entries related to insecure file uploads (search for "insecure file upload" on the NVD website).
