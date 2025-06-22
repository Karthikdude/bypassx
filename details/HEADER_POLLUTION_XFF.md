# HEADER_POLLUTION_XFF Bypass Technique

## Overview

HEADER_POLLUTION_XFF is a bypass technique that exploits vulnerabilities in web applications that rely solely on the `X-Forwarded-For` (XFF) HTTP header for identifying the client's IP address.  Attackers manipulate the XFF header to spoof their origin IP, bypassing security measures such as IP-based access controls, geolocation restrictions, and rate limiting.  This technique is particularly effective when the application doesn't properly validate or sanitize the XFF header, allowing attackers to inject multiple IP addresses, potentially including trusted internal IPs.

## Technical Details

- **Method**: HTTP Headers Manipulation
- **Vulnerability**: Improper validation or sanitization of the `X-Forwarded-For` HTTP header.  Trusting the XFF header without proper validation.
- **Impact**: Bypassing IP-based security controls, unauthorized access, spoofing location, circumventing rate limiting, and masking the attacker's true IP address.
- **Common Targets**: Web applications that use the XFF header for authentication, authorization, or rate limiting without proper validation.  This is common in reverse proxies and load balancers where the XFF header is used to track the client IP.

## Example

Let's say a web application only allows access from IP addresses within the 192.168.1.0/24 subnet.  An attacker with IP address 10.0.0.1 could craft a request with the following XFF header:

`X-Forwarded-For: 192.168.1.100, 10.0.0.1`

The application, if improperly configured, might only look at the first IP address in the comma-separated list (`192.168.1.100`) and grant access, even though the actual client IP is 10.0.0.1.

## How to Test

### Using curl

```bash
curl -H "X-Forwarded-For: 192.168.1.100, 10.0.0.1" "http://target.com/sensitive_page"
```
Replace `192.168.1.100` with a trusted IP and `10.0.0.1` with your actual IP address and `http://target.com/sensitive_page` with the target URL.

### Using Burp Suite

1. Intercept a request to the target application.
2. Go to the HTTP headers tab.
3. Add or modify the `X-Forwarded-For` header with the desired spoofed IP address(es), for example: `X-Forwarded-For: 192.168.1.100, 10.0.0.1`.
4. Forward the modified request.

### Manual Testing

1. Use your browser's developer tools (usually accessed by pressing F12).
2. Navigate to the "Network" tab.
3. Intercept a request.
4. Modify the request headers to include or change the `X-Forwarded-For` header.
5. Send the modified request.


## Security Implications

- **Bypasses IP-based access controls**:  This technique directly bypasses any security measures that rely on the client's IP address for authentication or authorization.
- **Spoofing location**: Attackers can mask their true location, enabling them to circumvent geolocation restrictions.
- **Circumventing rate limiting**: By using multiple spoofed IPs, attackers might evade rate-limiting mechanisms.
- **Increased attack surface**:  Improper validation allows attackers to potentially inject malicious code or commands into the XFF header, leading to further vulnerabilities.

## Recommendations for Defenders

- **Validate XFF header**: Never blindly trust the `X-Forwarded-For` header.  Implement robust validation checks.  Consider using a trusted reverse proxy and only trust its reported IP.
- **Prioritize trusted headers**: Rely on headers from your trusted reverse proxy instead of directly using XFF.
- **Use client certificates**: Employ client certificates for stronger authentication.
- **Utilize other authentication methods**: Employ robust authentication mechanisms such as OAuth 2.0 or OpenID Connect.
- **Restrict access based on other factors**:  Implement multi-factor authentication (MFA) or other factors like user roles and permissions.
- **WAF/security tool configurations**: Configure your WAF to detect and block suspicious XFF headers (e.g., long lists of IPs, private IPs, invalid formats).
- **Regular security assessments**: Conduct regular penetration testing and vulnerability assessments to identify and address vulnerabilities.
- **Secure coding practices**: Develop secure coding practices and follow the principle of least privilege.

## Related Techniques

- IP Spoofing
- HTTP Header Injection
- Server-Side Request Forgery (SSRF)

## References

- OWASP API Security Top 10
- [Various blog posts and research papers on XFF header vulnerabilities (search online)]  (Note:  Providing specific links here would require extensive research and potentially link to outdated or inaccurate information.  A search for "X-Forwarded-For vulnerability" will yield relevant results.)

