# CORS_PREFLIGHT_BYPASS Technique

## Overview

The CORS_PREFLIGHT_BYPASS technique exploits weaknesses in how some web applications implement or enforce the Cross-Origin Resource Sharing (CORS) policy.  It leverages the fact that preflight requests (OPTIONS requests) are not always correctly implemented or handled, allowing attackers to bypass CORS restrictions and access resources from different origins without proper authorization. This bypass often occurs when a server incorrectly handles the `Origin` header in the preflight request or fails to properly validate the `Access-Control-Allow-Origin` header response.

## Technical Details

- **Method**: HTTP Headers Manipulation
- **Vulnerability**: Improper CORS implementation, specifically handling of preflight requests (OPTIONS requests).
- **Impact**: Unauthorized access to resources from a different origin, leading to data breaches, data modification, or other security compromises.  This can be particularly dangerous if combined with other vulnerabilities like CSRF.
- **Common Targets**: Web applications that use AJAX or fetch requests to communicate with backend APIs and have improperly configured CORS policies.


## Example

Let's assume a vulnerable API endpoint at `https://vulnerable-api.com/api/data`.  A legitimate request from `https://example.com` would require a CORS policy allowing requests from `https://example.com`. However, if the preflight handling is flawed, it might be bypassed.

A malicious actor might attempt to access this API from `https://attacker.com` using a carefully crafted request that omits or manipulates the necessary headers to avoid triggering the preflight check or forcing an unexpected response.  This might involve sending a request with specific HTTP methods that aren't subject to preflight, or manipulating the `Origin` header in unexpected ways.


## How to Test

### Using curl

This example attempts to bypass the preflight check by omitting the `Origin` header:

```bash
curl -X POST -H "Content-Type: application/json" -d '{"key": "value"}' https://vulnerable-api.com/api/data
```

If the server does not properly validate the absence of the `Origin` header or doesn't enforce a preflight request appropriately, this might succeed.  More sophisticated attempts might involve altering the `Origin` header to a value the server unexpectedly accepts.

### Using Burp Suite

1. **Intercept the request:** Set Burp Suite to intercept HTTP traffic.
2. **Identify the AJAX/Fetch request:** Find the request accessing the vulnerable API endpoint.
3. **Modify the headers:**  Remove or modify the `Origin` header.  Experiment with sending different HTTP Methods (e.g. GET) to see if preflight is bypassed. You can also modify the `Origin` header to a value the server may not expect.
4. **Forward the request:** Forward the modified request to the server.
5. **Observe the response:** If the request succeeds without proper authorization, the CORS policy is vulnerable.

### Manual Testing

Manual testing involves using the browser's developer tools (Network tab) to examine and modify the requests made by a web application. Similar to Burp Suite, you would look for requests made to the vulnerable API, then remove or modify the `Origin` header to test for bypasses.  Examine the response status code; a successful response (200 OK) when it should have failed due to CORS indicates a vulnerability.

## Security Implications

- **Bypasses:** This bypasses the intended security provided by the CORS mechanism, effectively rendering it useless.
- **Risks:** Allows unauthorized access to sensitive data, enabling data breaches, account takeovers, and other malicious activities.
- **Real-world scenarios:** An attacker could steal user data, manipulate application state, or perform other attacks by bypassing CORS checks.  Combining this with other vulnerabilities, such as XSS, can magnify the impact.


## Recommendations for Defenders

- **Detect:** Monitor server logs for unexpected requests, especially those originating from unfamiliar domains with missing or manipulated `Origin` headers. Implement robust logging and intrusion detection systems.
- **Mitigation:**  Implement a strict and properly configured CORS policy, validating the `Origin` header rigorously. Ensure that your preflight checks are correctly implemented and handle all HTTP methods appropriately. Do not rely solely on the `Origin` header for authorization. Consider other mechanisms like JWT, OAuth.
- **Secure coding:** Use libraries and frameworks that provide secure handling of CORS.  Avoid manual handling of CORS headers unless absolutely necessary and deeply understand the implications.
- **WAF/security tool configurations:** Configure your WAF to detect and block requests with manipulated or missing `Origin` headers, or unusual request patterns indicative of bypass attempts.


## Related Techniques

- CSRF (Cross-Site Request Forgery)
- XSS (Cross-Site Scripting)
- Other CORS bypass techniques (e.g., exploiting misconfigurations in `Access-Control-Allow-Origin` handling)


## References

- [OWASP CORS Cheat Sheet](https://owasp.org/www-project-top-ten/2017/A10_2017-A10_Cross-site_request_forgery_(CSRF)) (Relevant section on CORS)
-  Various blog posts and research papers on CORS bypass techniques (search for "CORS bypass" on security research sites).  Specific links would depend on the newest research findings.
-  Burp Suite, OWASP ZAP (Tools that can be used for testing and identifying this vulnerability)
