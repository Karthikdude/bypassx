# ORIGIN_IP_BYPASS Technique

## Overview

The ORIGIN_IP_BYPASS technique exploits vulnerabilities in web applications that rely solely on the `X-Forwarded-For` (XFF) header or other similar headers to identify the client's origin IP address for access control or security checks.  This technique involves manipulating or spoofing these headers to bypass intended restrictions, allowing access from unauthorized IP addresses or networks.  The attacker crafts requests with forged XFF headers, effectively masking their real IP address and appearing as if the request originates from a trusted source.

## Technical Details

- **Method**: HTTP Headers Manipulation
- **Vulnerability**: Insufficient validation of client IP address; reliance on untrusted HTTP headers (`X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, etc.) for authorization or access control.  This often stems from a lack of proper IP address verification using trusted sources like the `REMOTE_ADDR` server variable.
- **Impact**: Unauthorized access to restricted resources, data breaches, privilege escalation, denial-of-service (DoS) attacks if combined with other techniques.
- **Common Targets**: Web applications with geolocation features, IP-based access controls, rate limiting mechanisms that solely rely on untrusted headers.


## Example

Let's assume a web application allows access only from the IP address 192.168.1.100.  A malicious actor with IP address 10.0.0.1 wants to access this application.  They can forge the XFF header to bypass the restriction:

**Malicious Request (using curl):**

```bash
curl -H "X-Forwarded-For: 192.168.1.100" "https://vulnerable-app.com/restricted"
```

This request will present the server with a forged XFF header claiming the origin IP is 192.168.1.100, potentially granting access even though the actual source IP is 10.0.0.1.


## How to Test

### Using curl

The example above demonstrates how to use curl to test the vulnerability. Replace `"https://vulnerable-app.com/restricted"` with the actual URL of the target application and `"192.168.1.100"` with the IP address the application is supposed to allow.

### Using Burp Suite

1. **Proxy Intercept:** Configure Burp Suite as your browser's proxy.
2. **Access Target:** Attempt to access the restricted resource.
3. **Intercept Request:** Intercept the request in Burp Suite's Proxy history.
4. **Modify Header:**  Add or modify the `X-Forwarded-For` header (or other relevant headers like `X-Real-IP`, `X-Client-IP`) to reflect a permitted IP address.
5. **Forward Request:** Forward the modified request to the target server.
6. **Observe Response:** Check if access is granted.  If successful, the vulnerability exists.

### Manual Testing

This is difficult to do manually without developer tools.  Browsers usually don't allow direct modification of outgoing headers easily.  However, using a browser extension that provides header manipulation capabilities can enable similar testing.


## Security Implications

- **Bypasses:** This bypasses IP-based access controls and security mechanisms that rely solely on untrusted HTTP headers.
- **Risks:** Unauthorized access, data breaches, escalation of privileges, potential for further attacks.
- **Attack Scenarios:**  An attacker could access sensitive data, manipulate application functionality, or launch further attacks against the system, all masked by a forged origin IP.


## Recommendations for Defenders

- **Detection:** Log and monitor HTTP header values and compare them with the `REMOTE_ADDR`.  Unusual discrepancies can indicate potential bypass attempts.  Implement intrusion detection systems (IDS) and security information and event management (SIEM) systems to detect suspicious patterns.
- **Mitigation:** Do **not** rely solely on `X-Forwarded-For` or similar headers for access control.  Always verify the client's IP address using the server's `REMOTE_ADDR` variable.  Employ a robust web application firewall (WAF) configured to detect and block requests with manipulated headers.
- **Secure Coding Practices:** Implement strict input validation and sanitization for all incoming data, including HTTP headers.
- **WAF/Security Tool Configurations:** Configure your WAF to block or flag requests containing suspiciously forged headers.


## Related Techniques

- HTTP Header Injection
- SQL Injection (if access control relies on database queries)
- Cross-Site Request Forgery (CSRF) (if CSRF protection is bypassed leading to unauthorized access based on the IP)


## References

- OWASP Top 10: [Insert relevant OWASP link referencing insecure usage of HTTP headers]
- [Add links to relevant CVE entries, blog posts, or research papers about this technique]
- [List any relevant security tools that can detect or mitigate this vulnerability]

