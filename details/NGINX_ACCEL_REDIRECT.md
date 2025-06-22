# NGINX_ACCEL_REDIRECT Bypass Technique

## Overview

The NGINX_ACCEL_REDIRECT bypass technique exploits a vulnerability in Nginx configurations using the `ngx_http_upstream_module` and specifically the `accel` directive.  This directive is intended for caching and accelerating static content. However, if misconfigured, it can allow attackers to redirect requests to arbitrary locations, bypassing intended security measures such as authentication or authorization checks.  This is achieved by manipulating the request in a way that causes Nginx to incorrectly interpret it and forward the request to a location controlled by the attacker.  Essentially, it leverages the intended functionality of the `accel` directive for malicious purposes.

## Technical Details

- **Method**: HTTP Header Manipulation, URL Manipulation (depending on misconfiguration)
- **Vulnerability**: Misconfiguration of Nginx's `ngx_http_upstream_module` (specifically the `accel` directive) allowing redirect manipulation.  This often arises when improperly handling user-supplied input in the request URL or headers.
- **Impact**: Arbitrary redirection, bypassing authentication/authorization, session hijacking, disclosure of sensitive information, potential for further attacks (e.g., XSS, CSRF) on the redirected location.
- **Common Targets**: Web applications using Nginx as a reverse proxy or load balancer with the `accel` directive configured to forward requests based on user-supplied data without proper validation.

## Example

Let's assume a vulnerable Nginx configuration is set up to use the `accel` directive and forwards requests to a backend server based on a header named `X-Accel-Redirect`.  An attacker could craft a request with the following header to redirect the request to an attacker-controlled domain:

```http
GET / HTTP/1.1
Host: vulnerable.example.com
X-Accel-Redirect: /../attacker.com/malicious.php
```

If the Nginx configuration does not properly sanitize or validate the `X-Accel-Redirect` header, this request will be redirected to `attacker.com/malicious.php`.  The `../` sequence could potentially allow traversal of directory structures.


## How to Test

### Using curl

```bash
curl -H "X-Accel-Redirect: /../attacker.com/malicious.php" "http://vulnerable.example.com/"
```

Replace `vulnerable.example.com` and `/../attacker.com/malicious.php` with the actual target and desired redirect location.  Note that this requires the target to be vulnerable to this specific attack vector.


### Using Burp Suite

1. Send a request to the target web application through Burp Suite's proxy.
2. Go to the request's HTTP headers tab.
3. Add a custom header named `X-Accel-Redirect` (or other relevant header based on the server’s configuration) and set its value to the desired redirect location, potentially including path traversal sequences (e.g., `../../`).
4. Forward the modified request to the target.
5. Observe if the request is redirected to the attacker-controlled location.


### Manual Testing

1. Use your browser's developer tools (usually accessed by pressing F12) to modify the outgoing HTTP request headers.
2. Add the `X-Accel-Redirect` header (or a similar header depending on the configuration) with the attacker-controlled redirect location.
3. Observe if the browser redirects to the manipulated location.


## Security Implications

- **Bypasses Authentication/Authorization:** This technique bypasses security mechanisms relying on URL validation or header checks alone.  It directly interacts with the Nginx layer bypassing any application-level security.
- **Session Hijacking:**  If the redirect leads to a page that sets or uses a session cookie, the attacker could potentially hijack the user's session.
- **Data Exfiltration:**  Redirecting to attacker-controlled servers can lead to leakage of sensitive information, depending on the nature of the redirected request.
- **Further Attacks:** The attacker might use the redirection to perform additional attacks like XSS or CSRF on the victim’s browser.

## Recommendations for Defenders

- **Input Validation:** Rigorously validate and sanitize any user-supplied input used in Nginx configuration directives such as `X-Accel-Redirect`.  This should include checking for path traversal attempts.
- **Disable or Restrict `accel` Directive:** If not absolutely necessary, disable the `accel` directive or severely limit its usage. Restrict access to only trusted internal locations.
- **Whitelist Allowed Destinations:** Instead of allowing arbitrary redirection, explicitly whitelist allowed destinations for the `accel` directive.
- **Regular Security Audits:** Conduct regular security audits of your Nginx configurations to identify and fix misconfigurations.
- **Web Application Firewall (WAF):** Configure your WAF to detect and block requests containing malicious `X-Accel-Redirect` or similar headers. Use custom rules if necessary.
- **Principle of Least Privilege:** Ensure that the Nginx user only has the necessary permissions for its tasks.


## Related Techniques

- Path Traversal
- Directory Traversal
- HTTP Header Injection
- Server-Side Request Forgery (SSRF)

## References

- [Relevant Nginx documentation on `ngx_http_upstream_module`](https://nginx.org/en/docs/ngx_http_upstream_module.html)  *(Adapt this to include a specific reference if a CVE exists related to misconfiguration)*
- [Add any relevant blog posts or research papers here]
- [Add any tools that can exploit or detect this issue here, if any exist]
