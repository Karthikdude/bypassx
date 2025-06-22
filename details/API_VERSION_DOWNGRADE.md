# API_VERSION_DOWNGRADE Bypass Technique

## Overview

API_VERSION_DOWNGRADE is a bypass technique that exploits vulnerabilities in APIs that lack proper versioning controls. Attackers leverage this technique by manipulating requests to target older, potentially insecure versions of an API, even if the application is designed to use a newer, more secure version. This often works by manipulating request parameters, headers, or the URL itself to force the API to revert to an outdated implementation.

## Technical Details

- **Method**: URL Manipulation, HTTP Headers, Parameter Tampering
- **Vulnerability**: Insufficient API Versioning, Lack of input validation on version parameters, Insecure default API version
- **Impact**: Access to deprecated functionality with known vulnerabilities, data breaches, unauthorized access, privilege escalation, denial-of-service.
- **Common Targets**: RESTful APIs, GraphQL APIs, any API with versioning mechanism (often via URL parameters like `/api/v1/`, `/api/v2/`, or headers such as `X-API-Version`).


## Example

Let's say a vulnerable API has versions v1 and v2.  Version v1 has a known SQL injection vulnerability in the `/users` endpoint, while v2 has this vulnerability patched.  A legitimate request to the secure v2 endpoint might look like:

`https://api.example.com/api/v2/users?id=1`

Using the API_VERSION_DOWNGRADE technique, an attacker could manipulate the URL to target the vulnerable v1 endpoint:

`https://api.example.com/api/v1/users?id=1;--`  (SQL injection attempt)

Or, if versioning is handled via a header, they might remove or modify it:

```http
GET /api/users?id=1 HTTP/1.1
Host: api.example.com
#X-API-Version: v2  (removed or changed to v1)
```

## How to Test

### Using curl

```bash
# Targeting a specific version via URL
curl "https://api.example.com/api/v1/users?id=1"

# Attempting to bypass versioning in a header
curl -H "X-API-Version: v1" "https://api.example.com/api/users?id=1"
```

### Using Burp Suite

1. Intercept a request to the latest API version.
2. Go to the "Proxy" tab -> "HTTP history".
3. Right-click the request and select "Send to Repeater".
4. In the Repeater tab, modify the URL to point to an older version (e.g., change `/v2/` to `/v1/` in the URL) or remove/modify the `X-API-Version` header.
5. Resend the modified request and analyze the response for any signs of vulnerabilities present in the older version.  Observe if the response differs from the original, indicating successful version downgrade.

### Manual Testing

1.  Identify the API versioning mechanism (URL parameter, header, etc.).
2.  Make a request to the latest API version through your browser's developer tools (Network tab).
3.  Modify the request to target an older version by changing the URL or header values.
4.  Observe the response; if you receive a different response than expected, or access functionality that should be unavailable, it could indicate a successful version downgrade.


## Security Implications

- **Bypasses security updates**: This technique bypasses security patches and mitigations implemented in newer API versions.
- **Exposure of vulnerabilities**:  Older API versions might contain known vulnerabilities (e.g., SQL injection, XSS, authentication flaws) that are absent in newer versions.
- **Data breaches**:  Successful exploitation can lead to unauthorized access to sensitive data.
- **Business disruption**:  Denial-of-service attacks targeting older, less robust API versions are possible.


## Recommendations for Defenders

- **Strict input validation**:  Validate all API version parameters to prevent manipulation.  Don't rely solely on client-side versioning.
- **Proper API versioning**: Implement robust API versioning using semantic versioning and deprecation policies.
- **Rate limiting and throttling**:  Limit requests to older API versions to mitigate denial-of-service attacks.
- **Regular security assessments**:  Conduct regular penetration testing and vulnerability assessments.
- **WAF/security tool configurations**: Configure your Web Application Firewall (WAF) to detect and block attempts to downgrade API versions.  Implement rules based on URL patterns or header values.
- **Deprecation and removal of old versions**:  Remove outdated API versions after a reasonable period.


## Related Techniques

- Parameter Tampering
- HTTP Header Manipulation
- Path Traversal


## References

- OWASP API Security Top 10
- [Relevant CVE entries (will vary based on specific vulnerabilities found in outdated API versions)]
- [Blog posts and research papers on API security best practices]  (Search for "API versioning security" or "API security best practices")


**Note:** This documentation provides information for educational purposes only.  Using this information for illegal activities is strictly prohibited.  Always obtain proper authorization before conducting security testing on any system.
