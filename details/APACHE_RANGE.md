# APACHE_RANGE Bypass Technique

## Overview

The APACHE_RANGE bypass technique exploits a potential vulnerability in how some web servers, particularly older Apache versions, handle `Range` headers in HTTP requests.  It allows attackers to potentially access files or parts of files outside the intended directory structure by manipulating the `Range` header value. This is especially relevant when dealing with file downloads or functionalities that involve serving files based on byte ranges.  It doesn't directly involve a specific vulnerability but rather leverages a misconfiguration or a lack of proper input validation related to how `Range` requests are processed.


## Technical Details

- **Method**: HTTP Headers Manipulation
- **Vulnerability**: Improper handling of `Range` headers in HTTP requests, lack of robust input validation on the range specification.  This often stems from insufficient sanitization or validation of the `Range` header value before it's used to access files on the server.
- **Impact**: Unauthorized access to files outside the web root directory, disclosure of sensitive information, potential for further exploitation if accessed files contain further vulnerabilities.
- **Common Targets**: Older versions of Apache web servers with insufficient input validation in their file serving modules. Applications that allow partial file downloads without proper safeguards.


## Example

Let's assume a vulnerable web application serves files from `/var/www/html/files/`.  A legitimate request for a partial download of `image.jpg` might look like this:

`GET /files/image.jpg HTTP/1.1`
`Range: bytes=0-1023`

An attacker could potentially use the APACHE_RANGE technique to try and access files outside this directory, for example `/etc/passwd`:

`GET /files/image.jpg HTTP/1.1`
`Range: bytes=-1023`  or `Range: bytes=10000000000000-` (extremely large offset)


## How to Test

### Using curl

```bash
curl -H "Range: bytes=-1024" "http://target.com/files/image.jpg"
```
This sends a request with a negative byte range which might lead to the server revealing contents from before `image.jpg` in memory or file system.  Experimenting with different negative and extremely large positive values is crucial.  You might need to adjust the range value depending on the server's configuration and file system structure.


### Using Burp Suite

1.  Send a request for a file (e.g., `/files/image.jpg`) to the target application.
2.  In the "Proxy" tab, select the request.
3.  Go to the "Request" tab and add or modify the `Range` header.  Try various values, including negative numbers, very large numbers, and numbers exceeding the size of the file.
4.  Forward the modified request and analyze the response.  Check for unexpected content, errors indicating file access outside the expected directory, or partially downloaded content that suggests the server is revealing data from different locations.


### Manual Testing

1. Open your browser's developer tools (usually F12).
2.  Make a request to the server for a file.
3.  Modify the request headers (using the Network tab) to include a `Range` header with different values as described above.
4.  Observe the response for unusual content.

## Security Implications

- **Bypasses directory traversal protections:**  This technique bypasses traditional directory traversal protections that rely solely on path sanitization within the URL.
- **Data breach:** Can lead to unauthorized disclosure of sensitive files, configuration files, and source code.
- **Escalation of privileges:**  If the accessed files contain vulnerabilities, this could facilitate further attacks.
- **Real-world attack scenarios:**  An attacker could use this to retrieve sensitive configuration files, customer data, or source code.


## Recommendations for Defenders

- **Input validation:** Implement robust input validation on all user-supplied data, including the `Range` header.  Reject any requests with invalid or out-of-range values.
- **Restrict access:** Use appropriate file access controls to limit access to sensitive files.
- **Secure file serving:** Use a secure file-serving mechanism that properly handles requests and prevents unauthorized access based on range specifications.
- **Regular security audits:** Conduct regular security audits and penetration testing to identify vulnerabilities.
- **WAF/security tool configurations:**  Configure your WAF to detect and block requests with potentially malicious `Range` headers.  Look for unusually large or negative byte ranges.
- **Upgrade to latest versions**: Ensure your web server software is up-to-date with the latest security patches.


## Related Techniques

- Directory Traversal
- HTTP Parameter Pollution
- LFI/RFI


## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/) (relevant to insecure design)
-  No specific CVE exists for this generalized technique, as it relies on misconfigurations rather than a specific vulnerability in a single software component.


Note: This technique's success highly depends on the specific implementation of the web server and its handling of the `Range` header.  It's not a universally effective exploit, but a potential vulnerability to watch out for, particularly in legacy systems.
