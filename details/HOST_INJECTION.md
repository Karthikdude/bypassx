# HOST_INJECTION Bypass Technique

## Overview

HOST_INJECTION is a bypass technique that leverages vulnerabilities in how a web application handles the `Host` HTTP header.  By manipulating the `Host` header, an attacker can potentially access unintended resources or bypass security mechanisms designed to restrict access based on the hostname. This often occurs when an application doesn't properly validate the `Host` header before processing requests.

## Technical Details

- **Method**: HTTP Headers Manipulation
- **Vulnerability**: Improper validation or sanitization of the `Host` HTTP header. This often manifests when an application relies solely on the server's virtual host configuration instead of explicitly validating the `Host` header in the application's logic.
- **Impact**: Access to unauthorized resources, data breaches, internal network reconnaissance, and potentially complete server compromise if combined with other vulnerabilities.
- **Common Targets**: Web applications with poor input validation, especially those using reverse proxies or load balancers without proper header validation configuration. Applications relying solely on server-side configuration for access control are particularly susceptible.

## Example

Let's say a vulnerable application serves resources from `/admin` only if the `Host` header matches `example.com`.  An attacker could use a different `Host` header to bypass this restriction.

Suppose the legitimate request is:

`GET /admin/panel HTTP/1.1
Host: example.com`


An attacker could potentially send the following request:

`GET /admin/panel HTTP/1.1
Host: attacker.com`

If the application doesn't properly validate the `Host` header, it might still serve the `/admin/panel` resource, even though the request originated from a different domain.

## How to Test

### Using curl

```bash
curl -H "Host: attacker.com" "http://example.com/admin/panel"
```

This command sends a request to `http://example.com/admin/panel` with the `Host` header set to `attacker.com`. Replace `attacker.com` with any arbitrary hostname.


### Using Burp Suite

1. **Proxy Setup:** Configure your browser to use Burp Suite as its proxy.
2. **Intercept Request:** Make a legitimate request to a protected resource.  Burp Suite will intercept the request.
3. **Modify Host Header:** In the request editor, change the `Host` header to a different value.  For example, change `example.com` to `attacker.com`.
4. **Forward Request:** Forward the modified request to the server.
5. **Observe Response:** Observe if the application still provides access to the protected resource even with the modified `Host` header.


### Manual Testing

1. Use your browser's developer tools (usually accessed by pressing F12).
2. Navigate to the Network tab.
3. Make a request to the target resource.
4. Find the request in the Network tab.
5. Edit the request headers and change the `Host` header.
6. Click "Send" or press Enter to send the modified request.
7. Observe the response to see if the application behaves differently than expected.



## Security Implications

- **Bypasses access control mechanisms:** This technique bypasses application-level access controls relying solely on the `Host` header for authorization.
- **Data exposure:**  It can lead to the disclosure of sensitive data intended for specific hosts.
- **Server takeover (in conjunction with other vulnerabilities):**  If combined with other vulnerabilities like command injection, it can lead to complete server compromise.
- **Internal network reconnaissance:**  Successfully exploiting HOST_INJECTION might reveal internal hostnames and resources.


## Recommendations for Defenders

- **Validate the Host Header:**  Always explicitly validate the `Host` header on the server-side.  Do not solely rely on the server's virtual host configuration.
- **Use a Web Application Firewall (WAF):** Configure your WAF to detect and block requests with unexpected or malicious `Host` headers.
- **Input Sanitization:** Sanitize all user inputs including headers.
- **Principle of Least Privilege:** Ensure applications only have access to the resources they require.
- **Regular Security Audits and Penetration Testing:** Conduct regular security assessments to identify and address vulnerabilities.


## Related Techniques

- Open Redirect
- HTTP Parameter Pollution
- Server-Side Request Forgery (SSRF)


## References

- OWASP Top 10: A1: Broken Access Control (Often involves Host header vulnerabilities)
- [Insert relevant CVE links if applicable]
- [Insert links to relevant blog posts and research papers]


**Note:** This documentation provides information for educational and security research purposes only.  Attempting to exploit vulnerabilities without authorization is illegal and unethical.  Always obtain explicit permission before testing security measures on any system.
