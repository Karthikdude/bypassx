# CSP_HEADER_BYPASS Bypass Technique

## Overview

This technique focuses on bypassing Content Security Policy (CSP) headers implemented to mitigate Cross-Site Scripting (XSS) attacks.  CSP headers define a policy that restricts the resources a web page is allowed to load, including scripts, stylesheets, images, and other assets.  This bypass often leverages subtle misconfigurations or inconsistencies in the CSP implementation, allowing attackers to inject malicious content despite the presence of a CSP header.

## Technical Details

- **Method**: HTTP Headers,  URL Manipulation,  Data Injection
- **Vulnerability**: Misconfigured or incomplete Content Security Policy (CSP) headers.  This can include overly permissive directives, lack of `report-uri` or `report-to` for logging violations,  or inconsistencies between CSP directives and actual resource loading.
- **Impact**: XSS vulnerabilities, allowing arbitrary code execution in the victim's browser. This can lead to data theft, session hijacking, account takeover, and other serious compromises.
- **Common Targets**: Web applications with improperly configured CSP headers, particularly those relying on outdated or incomplete CSP directives.  Applications using dynamically generated CSP headers that are not properly sanitized are especially vulnerable.


## Example

Let's say a website has a CSP header like this:

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline';
```

This policy allows scripts from the same origin (`'self'`) and inline scripts (`'unsafe-inline'`).  An attacker might try to exploit this by injecting a `<script>` tag with inline JavaScript, which is permitted.  However, a more sophisticated bypass could involve:

1. **Using `nonce` incorrectly:**  If the site uses a `nonce` to whitelist inline scripts but does not properly generate unique nonces for each request, an attacker might be able to guess or reuse a nonce to execute malicious code.
2. **Leveraging `unsafe-eval` (if present):** If the CSP allows `unsafe-eval`,  an attacker can use techniques like `eval()` or `Function()` to execute malicious code.
3. **Exploiting a missing `img-src` directive:** If the `img-src` directive is missing, the attacker could use an `<img>` tag to fetch and execute a malicious script from an external domain.

## How to Test

### Using curl

`curl` is limited in testing CSP bypasses directly, as it primarily focuses on HTTP requests and responses.  It cannot accurately reflect the browser's rendering engine and JavaScript execution.  CSP testing needs a browser-based approach.

### Using Burp Suite

1. **Intercept Requests:** Intercept HTTP requests to the target web application.
2. **Modify Headers/Body:**  Attempt to inject malicious script tags into the application's response body. Simultaneously modify or remove parts of the CSP header to see if the injection works. Experiment with different values for `script-src`, `style-src`, and other relevant directives.
3. **Observe Results:** Analyze the application's response and observe if the injected script executes. This can be observed using Burp's proxy functionality to see the effect of the request manipulation on the client-side.  Alternatively, use a browser extension to monitor JavaScript execution and inspect the console for errors or unexpected behavior.
4. **Repeat with different techniques:** Try different CSP bypass techniques described in the "Example" section.

### Manual Testing

1. **Inspect the CSP header:** Use your browser's developer tools (usually F12) to view the `Content-Security-Policy` header in the network tab.  This reveals the website's current CSP implementation.
2. **Attempt injection:**  Try injecting different types of script tags into forms, comments, or other parts of the webpage, aiming to bypass the restrictions defined in the CSP header.
3. **Observe browser behavior:** Monitor the browser console for errors or unusual behavior after injecting your code. This may indicate a successful bypass.


## Security Implications

- **Bypasses XSS protection:** This bypass negates the primary security benefit of a CSP header, leaving the application vulnerable to XSS attacks.
- **Data breaches:** Attackers can steal sensitive data (credentials, cookies, personal information).
- **Account takeover:**  Compromised accounts can be used for malicious purposes.
- **Site defacement:**  Attackers might alter the website's content.

## Recommendations for Defenders

- **Implement a robust CSP:** Use a comprehensive CSP that minimizes the use of `unsafe-inline` and `unsafe-eval`.  Employ `nonce` or `hash` for inline scripts and styles.
- **Regularly review and update CSP:** Ensure the CSP policy keeps pace with application changes.
- **Use a `report-uri` or `report-to` directive:**  This enables logging of CSP violations, providing valuable insights for identifying and addressing bypass attempts.
- **Employ a Web Application Firewall (WAF):** A well-configured WAF can help detect and block malicious requests that attempt to bypass the CSP.
- **Secure coding practices:**  Sanitize user inputs thoroughly to prevent injection vulnerabilities.
- **Regular security testing:** Perform penetration testing to identify weaknesses in the CSP implementation.

## Related Techniques

- XSS Reflection
- XSS DOM Based
- XSS Stored
- HTTP Header Injection

## References

- [OWASP CSP Cheat Sheet](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017_A5_Broken_Access_Control)
- [Mozilla CSP Documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
- [Various CVE entries related to CSP bypasses] (Search on CVE databases for relevant vulnerabilities)


Note:  Specific tools for automated CSP bypass testing are not readily available as a single package.  The testing relies on manual exploration or customization of existing tools like Burp Suite.
