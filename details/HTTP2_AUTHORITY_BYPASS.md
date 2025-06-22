# HTTP2_AUTHORITY_BYPASS Technique

## Overview

The HTTP2_AUTHORITY_BYPASS technique exploits a potential vulnerability in how some web applications and proxies handle HTTP/2 requests and the `authority` pseudo-header.  While the `authority` header is supposed to be used to specify the target server, some implementations may not properly validate or sanitize this header, allowing attackers to bypass intended access controls and potentially access unauthorized resources or servers.  This is particularly relevant in situations where access control is based on hostname or domain verification.

## Technical Details

- **Method**: HTTP Headers Manipulation
- **Vulnerability**: Improper validation or sanitization of the `authority` pseudo-header in HTTP/2 requests. This often occurs when a web application or reverse proxy relies solely on the `authority` header for access control without proper validation against other security mechanisms.
- **Impact**: Unauthorized access to resources, data exfiltration, server-side request forgery (SSRF), and other potential attacks depending on the specific application and its underlying architecture.
- **Common Targets**: Web applications, APIs, and reverse proxies that utilize HTTP/2 and rely solely or primarily on the `authority` header for authorization.

## Example

Let's assume a vulnerable web application only allows access to `https://example.com/private`.  An attacker could potentially use the `authority` header in an HTTP/2 request to target a different server or resource.

```http2
POST /private HTTP/2
authority: attacker.com
:path: /private
```

This request might successfully access `/private` on `attacker.com` if the server or reverse proxy doesn't properly check the `authority` against the actual hostname or perform appropriate authorization checks beyond the `authority` header.

## How to Test

### Using curl

This requires a server configured for HTTP/2.  Replace `attacker.com` and `https://example.com/private` with your target and path:

```bash
curl -v -H "authority: attacker.com" -X POST -H ":path:/private" --http2 https://example.com/private
```

The `-v` flag shows verbose output to help identify whether the request was processed as expected.

### Using Burp Suite

1. Intercept an HTTP/2 request to the target application.
2. In the request header, modify the `authority` pseudo-header to a different domain or hostname.
3. Forward the modified request to the server.
4. Observe the response. If the application allows access despite the modified `authority`, it may be vulnerable.

### Manual Testing

Manual testing requires a browser with HTTP/2 support and developer tools enabled.  Modify the request headers directly through the developer tools Network tab to change the `authority` header. This is generally more difficult than using `curl` or Burp Suite.


## Security Implications

- **Bypasses Access Controls:** This technique can bypass hostname-based access controls, allowing access to resources intended for different domains or servers.
- **SSRF Risk:**  It could enable Server-Side Request Forgery (SSRF) if the backend system processes the `authority` header without sufficient validation and allows requests to internal or external services.
- **Data Breach:**  If successful, the attacker gains access to sensitive data or functionality.


## Recommendations for Defenders

- **Validate Hostname:**  Do not solely rely on the `authority` header for authorization. Implement robust hostname validation using verified sources like the `Host` header, certificate validation, and other trusted mechanisms.
- **Input Sanitization:**  Sanitize and validate all HTTP headers, including the `authority` header, to prevent manipulation.
- **Secure Coding Practices:**  Develop secure code that adheres to established security principles and uses validated libraries.
- **WAF/Security Tool Configurations:** Configure your Web Application Firewall (WAF) or other security tools to detect and block requests with suspicious or unexpected values in the `authority` header.  Implement rules based on both header values and the source IP address.
- **Regular Security Audits:** Perform regular security assessments and penetration testing to identify and address potential vulnerabilities.


## Related Techniques

- HTTP Header Injection
- Host Header Injection
- Server-Side Request Forgery (SSRF)


## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/) (Relevant to A03: Broken Access Control)
- [Various blog posts and research papers on HTTP/2 security](Search for "HTTP/2 security vulnerabilities")  (Note: Specific links to relevant papers may require more contextual knowledge of recent findings)


**Note:**  This bypass technique is highly dependent on specific application implementations. Not all applications are vulnerable.  Responsible disclosure is crucial if you discover a vulnerability.
