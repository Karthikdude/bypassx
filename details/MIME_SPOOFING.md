# MIME_SPOOFING Bypass Technique

## Overview

MIME spoofing is a technique used to bypass security controls that rely on the `Content-Type` HTTP header to validate file uploads or other data inputs.  Attackers manipulate the `Content-Type` header to disguise malicious files (e.g., executable code) as harmless file types (e.g., images, text documents). This allows them to circumvent file type validation checks and potentially execute arbitrary code or cause other damage on the target system.

## Technical Details

- **Method**: HTTP Headers Manipulation
- **Vulnerability**: Insecure file upload handling, lack of robust file type validation beyond the `Content-Type` header, reliance on client-side validation only.
- **Impact**: Arbitrary code execution, denial of service, data breaches, malware installation, server compromise.
- **Common Targets**: Web applications with file upload functionalities, content management systems (CMS), forums, and any system that processes uploaded files based solely on the `Content-Type` header.


## Example

Let's say a web application allows users to upload images.  A malicious user could attempt to upload a malicious PHP script disguised as an image. They would craft the HTTP request to include the following:

```http
POST /upload.php HTTP/1.1
Host: vulnerable.example.com
Content-Type: image/jpeg
Content-Disposition: form-data; name="userfile"; filename="evil.jpg"
Content-Length: [size of file]

<?php system("ls -la"); ?>
```

While the `Content-Type` header claims it's a JPEG image, the actual content is malicious PHP code.  If the server only validates the `Content-Type` header, it might accept the upload and execute the PHP code, potentially revealing sensitive information or allowing for remote code execution.


## How to Test

### Using curl

```bash
curl -X POST -H "Content-Type: image/jpeg" -H "Content-Disposition: form-data; name=\"userfile\"; filename=\"evil.php\"" -d "<?php phpinfo(); ?>" http://vulnerable.example.com/upload.php
```

Replace `vulnerable.example.com/upload.php` with the target URL and adjust the payload accordingly.  This command attempts to upload a PHP file containing `phpinfo()` as a JPEG.


### Using Burp Suite

1. Identify a file upload functionality on the target web application.
2. Use Burp Suite's Proxy to intercept the file upload request.
3. Modify the `Content-Type` header to a different value (e.g., `application/x-sh` for a shell script or `text/html` for HTML code).
4. Change the filename extension to match the spoofed `Content-Type`.
5. Modify the request body to contain the malicious payload.
6. Forward the modified request to the server.
7. Observe the server's response to see if the malicious file was successfully uploaded and executed.


### Manual Testing

1. Open your browser's developer tools (usually F12).
2. Navigate to the file upload functionality.
3. Use the Network tab to intercept the upload request.
4. Modify the `Content-Type` header and filename using the request editor.
5. Ensure the file contents are malicious.
6. Send the modified request.
7. Check for signs of successful exploitation (e.g., unexpected output, file execution).


## Security Implications

- **Bypasses input validation:**  MIME spoofing bypasses basic checks relying only on the `Content-Type` header.
- **Code execution:**  Leads to arbitrary code execution if the server processes uploaded files without proper validation.
- **Data breaches:**  Compromised servers can lead to data leaks and exfiltration.
- **Server compromise:** Full server takeover is possible if the attacker gains code execution privileges.

## Recommendations for Defenders

- **Validate file types beyond the `Content-Type` header:**  Use file magic numbers (file signatures) to verify the actual file type.
- **Content inspection:**  Scan uploaded files for malicious code using antivirus software and static/dynamic analysis tools.
- **File type whitelisting:** Restrict allowed file types to a very limited set of safe formats.
- **Safe file handling:**  Store uploaded files in a secure location with limited permissions.
- **Secure coding practices:**  Follow secure coding guidelines to prevent vulnerabilities.
- **WAF/security tool configurations:**  Configure your WAF to block requests with suspicious `Content-Type` headers or suspicious file contents.  Implement robust file upload filtering rules.


## Related Techniques

- File type juggling
- Content-Type header injection
- Server-Side Request Forgery (SSRF)


## References

- OWASP File Upload Cheat Sheet
- CWE-434: Unvalidated Upload of Files with Dangerous Type
- Various blog posts and security advisories related to file upload vulnerabilities (search for "file upload vulnerability bypass")


Note: This documentation is for educational purposes only.  Using these techniques for malicious purposes is illegal and unethical.  Always obtain explicit permission before testing security vulnerabilities on any system.
