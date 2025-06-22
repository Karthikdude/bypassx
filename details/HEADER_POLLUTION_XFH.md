# HEADER_POLLUTION_XFH Bypass Technique

## Overview

The HEADER_POLLUTION_XFH technique bypasses security mechanisms that rely on the `X-Frame-Options` (XFO) header to prevent clickjacking attacks.  It achieves this by polluting the HTTP response with multiple `X-Frame-Options` headers, exploiting a potential vulnerability in how some systems process and prioritize these headers.  Instead of relying on a single, authoritative `X-Frame-Options` header, an attacker might inject multiple conflicting headers, hoping that the application processes a less restrictive one, enabling the clickjacking.

## Technical Details

- **Method**: HTTP Headers Manipulation
- **Vulnerability**: Inconsistent or improper handling of multiple, conflicting `X-Frame-Options` headers by the web application. This often stems from multiple parts of the application (e.g., different frameworks or libraries) setting the header independently.
- **Impact**: Successful exploitation allows an attacker to embed the vulnerable website within an iframe on a malicious site, potentially tricking users into performing actions (e.g., making payments, changing account settings) on the victim website within a hidden or disguised iframe. This leads to unauthorized actions and data breaches.
- **Common Targets**: Web applications built using multiple frameworks or libraries, or those lacking robust header management mechanisms.


## Example

Let's assume a vulnerable web application sets the `X-Frame-Options` header twice:

Response 1 (from a legacy module): `X-Frame-Options: ALLOW-FROM uri.example.com`
Response 2 (from a newer module): `X-Frame-Options: SAMEORIGIN`

An attacker could potentially exploit this by crafting a request that triggers both responses, leading to some browsers interpreting the `ALLOW-FROM` directive as the final decision, allowing embedding from `uri.example.com`.

## How to Test

### Using curl

This is difficult to test reliably with `curl` alone as it would require manipulating the server-side response to inject multiple headers.  `curl` is primarily for sending requests, not for controlling the server's response behavior.  To test this, you'd need a server environment that allows injecting multiple conflicting headers.

### Using Burp Suite

1. **Intercept:** Intercept the HTTP response from the target web application.
2. **Modify:** Add a second `X-Frame-Options` header with a different value.  For example, add `X-Frame-Options: ALLOW-FROM attacker.com` if the original header is `X-Frame-Options: SAMEORIGIN`.
3. **Forward:** Forward the modified response to the browser.
4. **Test:** Attempt to frame the target website in an iframe hosted on `attacker.com`. If successful, the vulnerability is likely present.  Note: Success is highly dependent on browser behavior and how it interprets conflicting headers.

### Manual Testing

Manual testing is impractical without server-side control. You cannot directly manipulate the response headers from the browser.


## Security Implications

- **Bypass of Clickjacking Protection:** This bypass negates the primary security benefit provided by the `X-Frame-Options` header.
- **Data Breaches:** Allows attackers to perform actions on behalf of the user without their knowledge or consent.
- **Session Hijacking:** Potentially allows attackers to steal session cookies through hidden iframes.
- **Phishing Attacks:**  Increases the success rate of phishing attacks by making them more believable and less noticeable.

## Recommendations for Defenders

- **Detect:** Use a web application scanner that checks for inconsistent `X-Frame-Options` headers in the response. Inspect your application's code carefully for multiple instances setting the header.
- **Mitigation:** Implement a robust header management system, ensuring only one authoritative entity sets the `X-Frame-Options` header. Avoid using multiple frameworks or libraries that independently set this header. Use a standardized method of header setting across the whole application.
- **Secure Coding Practices:**  Strictly control header setting, possibly centralizing this logic in one location within the application.
- **WAF/security tool configurations:**  While WAFs can't directly prevent this vulnerability, they can help identify inconsistencies in headers by logging unusual header patterns.  Modern WAFs might have more advanced functionality to detect header conflicts.


## Related Techniques

- Clickjacking (general technique)
- HTTP Header Injection (broader category)
- Response Splitting (related to injecting additional headers)


## References

- [OWASP Clickjacking Prevention Cheat Sheet](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017_A10_Insufficient_Protection_Against_Clickjacking)
-  [Various browser developer documentation on X-Frame-Options](Search for individual browser documentation)  (Note: browser behavior regarding multiple conflicting headers may vary).

**(Note:  No specific CVE is associated with this precise bypass technique, as it relies on misconfiguration and inconsistency rather than a specific vulnerability in a library or framework.)**
