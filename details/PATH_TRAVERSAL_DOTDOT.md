# PATH_TRAVERSAL_DOTDOT Bypass Technique

## Overview

The PATH_TRAVERSAL_DOTDOT technique exploits a vulnerability in web applications that allows attackers to access files and directories outside the intended webroot by manipulating the path component of a URL using ".." sequences.  Each ".." represents a traversal up one directory level.  This allows attackers to read sensitive files (like configuration files, source code, or database credentials), or potentially execute arbitrary code if the server allows file execution.

## Technical Details

- **Method**: URL Manipulation
- **Vulnerability**: Path Traversal vulnerability (CWE-22)
- **Impact**: Unauthorized access to sensitive files and directories, potential for remote code execution (RCE), data breach, and server compromise.
- **Common Targets**: File download functionalities, file upload functionalities with insufficient validation, web applications with poorly implemented file path handling.


## Example

Let's assume a vulnerable application exposes a file download functionality at `/download?file=filename`.  A legitimate request might be `/download?file=images/logo.png`.  Using PATH_TRAVERSAL_DOTDOT, an attacker might try:

`/download?file=../../../../etc/passwd`  (Attempting to read the `/etc/passwd` file on a Linux system)

or

`/download?file=../../../../windows/system32/drivers/etc/hosts` (Attempting to read the hosts file on a Windows system)


## How to Test

### Using curl

```bash
curl "http://target.com/download?file=../../../../etc/passwd"
```

Replace `http://target.com/download?file=` with the actual vulnerable URL.  This command attempts to download the `/etc/passwd` file.  Adapt the `../../..` sequence to reach the desired directory.

### Using Burp Suite

1. **Proxy Intercept:** Intercept the HTTP request for a file download.
2. **Modify the Request:**  Locate the parameter containing the filename (e.g., `file`).
3. **Inject "..":**  Add sequences of ".." before the legitimate filename to traverse up the directory structure.  For example, change `file=images/logo.png` to `file=../../../../etc/passwd`.
4. **Forward the Request:** Forward the modified request to the server.
5. **Analyze the Response:** Examine the response to see if sensitive information was revealed. Burp Suite can help by highlighting any potentially sensitive data.

### Manual Testing

1. **Identify a File Download Function:** Find a functionality within the application that allows downloading files.
2. **Modify the URL:**  Manually add ".." sequences to the filename parameter in the URL, similar to the curl and Burp Suite examples.
3. **Observe the Results:** Check if the browser downloads unexpected files or displays error messages that reveal file paths.


## Security Implications

- **Bypasses Input Validation:** This technique bypasses basic input validation that might check for allowed characters or extensions but doesn't verify the full path.
- **Data Exposure:** Leads to the disclosure of sensitive configuration files, source code, private user data, and potentially database credentials.
- **RCE (Remote Code Execution):** If the server allows file execution, an attacker could upload a malicious script and then access it using this technique, leading to a complete server compromise.
- **Real-world Attack Scenarios:**  Attackers might use this to gain initial access to a system, escalate privileges, or exfiltrate sensitive data.


## Recommendations for Defenders

- **Strict Input Validation:**  Validate *all* user-supplied inputs, including file paths.  Don't rely solely on client-side validation.  Use allowlisting rather than blacklisting.
- **Canonicalization:** Use a secure path canonicalization library to normalize and sanitize file paths. This prevents manipulation with "../" sequences.
- **Restrict Directory Access:** Configure the web server to restrict access to sensitive directories outside the webroot.
- **Principle of Least Privilege:** Run web applications with the minimum necessary privileges.
- **WAF/Security Tool Configurations:** Configure your WAF to detect and block requests containing excessive ".." sequences or suspicious path traversal attempts.  Regularly update your WAF rules.
- **Secure Coding Practices:** Avoid using potentially vulnerable functions like `eval()` or `exec()` that could lead to RCE if combined with path traversal.
- **Regular Security Audits:** Conduct regular penetration testing and vulnerability scans to identify and address potential path traversal vulnerabilities.


## Related Techniques

- Directory Traversal (using other characters to traverse directories)
- HTTP Parameter Pollution
- Local File Inclusion (LFI)
- Remote File Inclusion (RFI)


## References

- [OWASP Top 10 - A07:2021-Broken Access Control](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2021_A07_Broken_Access_Control)  (While not directly about this specific technique, it highlights the overall vulnerability class)
- Various CVE entries related to Path Traversal vulnerabilities (search for "CVE path traversal" on the NVD website)
- Numerous blog posts and security research papers on path traversal vulnerabilities (search for "path traversal bypass techniques" on Google Scholar or security blogs).
