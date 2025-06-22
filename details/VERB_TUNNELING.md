# VERB_TUNNELING Bypass Technique

## Overview

VERB_TUNNELING is a bypass technique used to circumvent web application firewalls (WAFs) and other security mechanisms that filter requests based on the HTTP method (e.g., GET, POST, PUT, DELETE).  It involves embedding the intended HTTP verb (method) within the request body or URL parameters, effectively "tunneling" it past filters that only examine the HTTP method specified in the request line. This allows attackers to execute actions (like updates or deletions) that would otherwise be blocked.

## Technical Details

- **Method**: HTTP Parameter/Body Manipulation, URL Manipulation
- **Vulnerability**:  Insufficient input validation and sanitization, reliance on superficial HTTP method checks in WAFs or application logic.  Essentially exploits the fact that some security measures only check the initial HTTP method and not the data itself.
- **Impact**: Unauthorized data modification or deletion, potential for complete application compromise depending on the context.  Allows attackers to perform actions they shouldn't be able to.
- **Common Targets**: Web applications with weak input validation, WAFs with limited or improperly configured method filtering. Applications that handle user-supplied data without proper sanitization are particularly vulnerable.


## Example

Let's assume a vulnerable application allows users to update their profile via a POST request to `/profile/update`.  A WAF might be configured to block any non-GET requests to this endpoint.  Using VERB_TUNNELING, an attacker could craft a request like this:

**Malicious Request (POST data):**

```
_method=DELETE
```

The attacker could then send a GET request to `/profile/update` with the above data.  If the application improperly handles the `_method` parameter, it might interpret the `DELETE` request, effectively deleting the user profile despite the initial GET method. This exploits the fact that the application might be looking for the request method from within the body or parameters, rather than solely relying on the HTTP method declared in the request line.


## How to Test

### Using curl

```bash
curl -X GET -d "_method=DELETE" "http://vulnerable-app/profile/update"
```

This command sends a GET request but includes the `_method=DELETE` parameter in the request body.  Replace `"http://vulnerable-app/profile/update"` with the actual URL.

### Using Burp Suite

1. Intercept a legitimate GET request to `/profile/update`.
2. In the request body, add `_method=DELETE` or similar parameters depending on what the application looks for.
3. Forward the modified request.
4. Observe the application's response to see if the DELETE action was successfully executed.  Check for relevant changes in the application state.

### Manual Testing

1. Use your browser's developer tools (usually accessible by pressing F12) to modify a GET request to include the `_method` parameter in the request body.
2. Send the modified request.
3. Observe the application's response.


## Security Implications

- **Bypasses**:  Bypasses WAF rules that rely solely on HTTP method inspection. By passes input validation that only checks for GET/POST and ignores unexpected data in the request body or parameters.
- **Potential Risks**: Unauthorized data modification, deletion, or any other action allowed by the underlying application logic.  Can lead to data breaches or application compromise.
- **Real-world Attack Scenarios**:  Deleting user accounts, modifying sensitive data, executing arbitrary code (if the application has vulnerabilities beyond just method filtering).


## Recommendations for Defenders

- **Detect**: Implement robust input validation and sanitization.  WAF rules should check not just the HTTP method but also the request body for unexpected commands or parameters (like `_method`).  Monitor application logs for unusual activity, especially involving unexpected verbs or manipulation of parameters.
- **Mitigation Strategies**:  Do not rely solely on the HTTP method for authorization.  Verify actions based on the user's privileges and the request data, not just the request method. Properly validate and sanitize *all* inputs, including HTTP parameters and the request body.  Use parameterized queries to prevent SQL injection which can be combined with HTTP verb tunneling.
- **Secure Coding Practices**:  Avoid processing user-supplied data directly without sanitization or validation. Use appropriate frameworks and libraries that perform secure handling of HTTP requests.  Always validate user permissions before executing any action.
- **WAF/security tool configurations**: Configure WAFs to inspect the request body and parameters for potentially malicious commands.  Use more advanced WAF features beyond basic method checking.  Consider using a more modern, robust WAF or other security tools capable of dynamic analysis and context-aware security.


## Related Techniques

- HTTP Parameter Pollution
- HTTP Header Injection
- SQL Injection (often used in conjunction with verb tunneling to execute malicious SQL commands)


## References

- OWASP Web Application Security Verification Standard (WASC) - Details on various web application vulnerabilities including improper input validation.  (No specific CVE as this is a technique, not a specific vulnerability)
- Various blog posts and articles on WAF bypass techniques (search for "WAF bypass techniques" on security blogs).  Many security researchers have documented examples of VERB_TUNNELING in practice.
- (Add specific links to relevant blog posts or research papers as you find them)
- (Note:  Tools don't directly "implement" this technique, but tools like Burp Suite can be used to test for and exploit it.)
