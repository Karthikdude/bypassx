# CACHE_DECEPTION_XFH Bypass Technique

## Overview

CACHE_DECEPTION_XFH is a bypass technique that leverages the `X-Forwarded-Host` header to deceive caching mechanisms and potentially bypass security controls like web application firewalls (WAFs) or origin servers' access controls.  It exploits the trust placed in the `X-Forwarded-Host` header by some applications, which can be manipulated to point to a different hostname than the actual request's origin, thus allowing an attacker to access resources or perform actions intended for a different domain or subdomain.  This is especially effective against caches that blindly trust this header, leading to the delivery of cached responses intended for a different host.

## Technical Details

- **Method**: HTTP Header Manipulation
- **Vulnerability**: Improper validation or reliance on the `X-Forwarded-Host` header.  This often combines with a vulnerability in how the application handles caching.
- **Impact**: Unauthorized access to resources, bypass of security controls (WAFs, ACLs), cache poisoning, data exfiltration, and potential for further attacks.
- **Common Targets**: Applications utilizing caching mechanisms (CDNs, reverse proxies, local caches) that trust the `X-Forwarded-Host` header without proper validation against the actual host or origin.


## Example

Let's assume a vulnerable application accessible at `https://www.example.com` caches responses. An attacker wants to access a resource intended for `https://admin.example.com`.

The attacker crafts a request to `https://www.example.com/admin/secret.txt` with the following header:

`X-Forwarded-Host: admin.example.com`

If the caching mechanism trusts this header and previously cached a response for `https://admin.example.com/admin/secret.txt`, it will return that cached response to the attacker, even though the request originated from `www.example.com`.  This is because the cache uses `X-Forwarded-Host` to determine which cached response to return.


## How to Test

### Using curl

```bash
curl -H "X-Forwarded-Host: admin.example.com" "https://www.example.com/admin/secret.txt"
```

This command sends a request to `https://www.example.com/admin/secret.txt` with the `X-Forwarded-Host` header set to `admin.example.com`.

### Using Burp Suite

1. Intercept a request to a target URL (e.g., `https://www.example.com/somepage.html`).
2. In the request headers tab, add a new header: `X-Forwarded-Host: target.example.com` (replace `target.example.com` with the desired target host).
3. Forward the modified request.
4. Observe if the response is intended for `target.example.com` instead of `www.example.com`.

### Manual Testing

1. Use your browser's developer tools (usually accessible by pressing F12) to modify the request headers.
2. Add the `X-Forwarded-Host` header with the desired target host.
3. Send the modified request.
4. Inspect the response to see if it matches the target host's content instead of the actual host.



## Security Implications

- **Bypass of WAFs/ACLs:**  Attackers might bypass WAF rules or access control lists based on the host header.
- **Cache Poisoning:**  Successful exploitation can lead to poisoned cache entries, serving malicious content to legitimate users.
- **Data Exfiltration:**  Confidential data might be leaked via cached responses.
- **Escalation of privileges:** Access to resources intended for administrative users or restricted functionalities.

## Recommendations for Defenders

- **Strict Header Validation:**  Validate the `X-Forwarded-Host` header against the actual host or origin server's address. Do not trust it blindly.
- **Disable or Sanitize:**  Consider disabling the `X-Forwarded-Host` header processing entirely if not strictly necessary.  If it's required, carefully sanitize and validate its value.
- **Strong Access Controls:**  Implement robust access control measures, ensuring that users have only access to resources they are explicitly authorized to access.
- **Proper Caching Configuration:**  Configure caching mechanisms to properly handle and validate the `X-Forwarded-Host` header, or to avoid caching sensitive content entirely.
- **WAF Rules:**  Implement WAF rules to detect and block requests with manipulated `X-Forwarded-Host` headers.
- **Regular Security Audits:** Conduct regular penetration testing and security audits to identify vulnerabilities.

## Related Techniques

- HTTP Header Injection
- Cache Poisoning
- Host Header Manipulation
- Server-Side Request Forgery (SSRF)

## References

- OWASP Top 10 (Relevant sections on Broken Access Control and Security Misconfiguration)
- [Insert relevant CVE numbers if applicable]
- [Insert links to relevant blog posts or research papers if applicable]
- [Insert links to security tools that might detect or mitigate this, e.g., ModSecurity rules]
