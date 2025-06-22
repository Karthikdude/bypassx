# X_METHOD_OVERRIDE Bypass Technique

## Overview

The X_METHOD_OVERRIDE technique exploits a vulnerability in web applications that improperly handle HTTP requests where the actual HTTP method (like PUT, DELETE, PATCH) is overridden by a parameter, typically named "_method" or similar, within the request body or query string.  This allows an attacker to trigger unintended actions, such as deleting data or modifying sensitive information, even if the application's frontend only allows submitting forms using the less dangerous POST method.

## Technical Details

- **Method**: HTTP Parameter Manipulation (primarily within the request body, sometimes the query string)
- **Vulnerability**: Improper handling of HTTP methods, lack of validation of parameters overriding HTTP verbs. This often stems from relying solely on the HTTP method reported by the client, without properly verifying it against the request's data.  Applications vulnerable often fail to distinguish between a legitimately intended POST with an overridden method and a malicious POST intent on changing the HTTP method.
- **Impact**: Unauthorized data modification or deletion, potential for escalation of privileges, data breaches, and complete application compromise depending on the affected functionality.
- **Common Targets**: Web applications using frameworks that don't properly enforce HTTP method validation, or those with custom implementations lacking sufficient checks.  Frameworks vulnerable in their default configurations can also be targets.


## Example

Let's say a vulnerable application has an endpoint `/users/123` that deletes a user with ID 123 when receiving a DELETE request.  An attacker could use a POST request with the `_method` parameter to effectively send a DELETE request:

**Malicious Request (POST):**

```http
POST /users/123 HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/x-www-form-urlencoded

_method=DELETE
```

This POST request, despite appearing as a POST, will likely trigger the DELETE functionality due to the `_method=DELETE` parameter, effectively deleting user 123.

## How to Test

### Using curl

```bash
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "_method=DELETE" "http://vulnerable-app.com/users/123"
```

This command sends a POST request with the `_method` parameter set to DELETE to the specified URL.  Replace `"http://vulnerable-app.com/users/123"` with the actual target URL.

### Using Burp Suite

1. Intercept a POST request to a vulnerable endpoint.
2. In the request's payload, add a parameter `_method=DELETE` (or another HTTP verb like PUT or PATCH).  Common parameter names besides `_method` include `_method`, `http_method`, `X-HTTP-Method-Override`, etc.
3. Forward the modified request.

### Manual Testing

1. Open the browser's developer tools (usually F12).
2. Find the Network tab.
3. Intercept a POST request to a sensitive endpoint (e.g., a form submitting data that might allow for an update or deletion).
4. Modify the request body to add `_method=DELETE` (or other relevant method) as a hidden form field or within the request body (depending on the application's implementation).
5. Resubmit the modified request.


## Security Implications

- **Bypasses authorization checks:** Attackers can bypass authorization mechanisms intended to restrict certain HTTP methods to authorized users only.
- **Data manipulation and deletion:** Allows attackers to modify or delete data they shouldn't have access to.
- **Privilege escalation:**  In some cases, this vulnerability can lead to privilege escalation by modifying user roles or permissions.
- **Denial of service (DoS):**  While less common with this specific vulnerability, it could be used to trigger actions that result in resource exhaustion.

## Recommendations for Defenders

- **Detect:**  Implement robust logging and monitoring to detect unusual HTTP method usage compared to what the application is designed for.  Look for requests where the method in the request line does not match the intended action based on parameter analysis.
- **Mitigation:**  Use framework features and security mechanisms to properly validate and enforce HTTP methods. Do not rely solely on the HTTP method present in the HTTP request line.  Inspect the HTTP verb based on explicit parameterization or request structure verification.
- **Secure coding practices:**  Never trust user-supplied input directly.  Always validate the HTTP method independently and consistently. Avoid using easily guessable parameter names for the override.
- **WAF/security tool configurations:** Configure your Web Application Firewall (WAF) to detect and block requests containing potentially malicious parameters such as `_method`. Consider rules based on the request method in the header and potential overrides within the body.


## Related Techniques

- CSRF (Cross-Site Request Forgery)
- Parameter Tampering
- HTTP Header Manipulation


## References

- OWASP Top 10 (A1: Injection, A3: Broken Authentication)
- [Various blog posts and research papers on HTTP method override vulnerabilities](Search for "HTTP method override vulnerability" on Google Scholar or security blogs)
- (Add links to relevant CVE entries if applicable)

