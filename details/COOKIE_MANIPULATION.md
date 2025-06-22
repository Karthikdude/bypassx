# COOKIE_MANIPULATION Bypass Technique

## Overview

Cookie manipulation involves altering or forging HTTP cookies to gain unauthorized access or modify application state.  This technique exploits weaknesses in how web applications handle and validate cookies, potentially leading to session hijacking, privilege escalation, or data manipulation.  Attackers can modify existing cookies, create new ones, or even delete crucial cookies to achieve their goals.

## Technical Details

- **Method**: HTTP Headers, Client-Side Manipulation
- **Vulnerability**: Insufficient cookie security measures (lack of HttpOnly, Secure, SameSite flags; predictable session IDs; lack of input validation on cookie values).  Session management flaws.  Cross-Site Scripting (XSS) vulnerabilities can often be leveraged to facilitate cookie manipulation.
- **Impact**: Session hijacking, unauthorized access, data modification or deletion, privilege escalation, account takeover, complete compromise of the web application.
- **Common Targets**: Web applications relying on session cookies for authentication and authorization; applications with weak session management; applications vulnerable to XSS.


## Example

Let's assume a vulnerable web application uses a cookie named `sessionid` to manage user sessions.  A legitimate user's cookie might look like this: `sessionid=a1b2c3d4e5f6`. An attacker could try several manipulations:

* **Session Hijacking:** Obtain the `sessionid` from a legitimate user (e.g., through XSS) and use it to impersonate that user.
* **Modifying Cookie Value:**  An attacker might try to change the `sessionid` to a known vulnerable value or inject malicious code if the application does not properly sanitize cookie content. For example, changing it to `sessionid=admin` if the application has a predictable session ID generation mechanism or vulnerable authorization.
* **Cookie Poisoning:**  If the application doesn't properly validate the cookie's origin, an attacker could create a new `sessionid` cookie with manipulated values and set it in the browser.

## How to Test

### Using curl

This example demonstrates setting a custom cookie with `curl`:

```bash
curl -H "Cookie: sessionid=attacker_session_id" "https://vulnerable-website.com/protected-page"
```

Replace `"attacker_session_id"` and `"https://vulnerable-website.com/protected-page"` with the actual values.  This command attempts to access a protected page using a forged session ID.

### Using Burp Suite

1. Intercept the HTTP request containing the cookie.
2. In the Burp Suite proxy, modify the cookie value in the request's header.
3. Forward the modified request.
4. Observe the application's response to check if the manipulation was successful.  You can use Burp's repeater to test multiple variations.

### Manual Testing

1. Open your browser's developer tools (usually by pressing F12).
2. Navigate to the "Application" or "Storage" tab.
3. Locate the cookies for the target website.
4. Modify the value of a relevant cookie (e.g., session ID).
5. Refresh the page and observe the application's response.  **Note:**  This is more limited as it relies on client-side cookies; `HttpOnly` cookies cannot be modified this way.

## Security Implications

- **Bypasses:** Authentication and authorization mechanisms, input validation, session management controls.
- **Potential Risks:** Data breaches, unauthorized access to sensitive information, financial loss, reputational damage, legal liabilities.
- **Real-world Attack Scenarios:**  Session hijacking in online banking, credential theft, account takeover in social media platforms, data manipulation in e-commerce sites.

## Recommendations for Defenders

- **Detection:**  Monitor for unusual cookie values, suspicious access patterns, and login attempts from unexpected locations.  Implement robust logging and alerting mechanisms.
- **Mitigation Strategies:** Use secure cookie flags (`HttpOnly`, `Secure`, `SameSite`), generate unpredictable session IDs, implement robust input validation, utilize strong session management techniques, regularly rotate session keys.
- **Secure Coding Practices:** Properly sanitize all user inputs, validate cookies on the server-side before using them, avoid storing sensitive data in cookies, enforce strong password policies.
- **WAF/security tool configurations:** Configure your WAF to detect and block suspicious cookie manipulation attempts.  Use a Web Application Firewall (WAF) to protect against malicious requests.

## Related Techniques

- Cross-Site Scripting (XSS)
- Session Fixation
- CSRF (Cross-Site Request Forgery)
- SQL Injection (to obtain session IDs)


## References

- OWASP Top 10 - Session Management
- [OWASP Cookie Security Cheat Sheet](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017_A10_Insufficient_Session_Management/)
- Various CVE entries related to session management vulnerabilities (search for "session management" on the NVD website).
