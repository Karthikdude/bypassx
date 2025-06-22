# TOKEN_MANIPULATION Bypass Technique

## Overview

Token manipulation involves altering or forging authentication tokens (e.g., JWTs, session IDs, CSRF tokens) to gain unauthorized access to a web application.  This technique exploits weaknesses in how tokens are generated, validated, or handled by the application.  Successful exploitation can lead to session hijacking, unauthorized data access, or complete account takeover.

## Technical Details

- **Method**: URL Manipulation, HTTP Headers, Cookie Manipulation, Parameter Tampering
- **Vulnerability**: Insufficient token validation, predictable token generation, lack of proper token expiry mechanisms, insecure token storage (e.g., in localStorage without proper protection), missing or weak CSRF protection.
- **Impact**: Unauthorized access to user accounts, data breaches, session hijacking, privilege escalation, application takeover.
- **Common Targets**: Web applications using session-based authentication, applications relying on JWTs or other token-based authentication mechanisms, applications with poorly implemented CSRF protection.

## Example

Let's assume a JWT (JSON Web Token) is used for authentication.  The token might contain user ID and roles.  A vulnerable application might not properly validate all claims within the JWT, allowing an attacker to modify the `role` claim to gain elevated privileges.

**Original JWT:** `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwicm9sZSI6InVzZXIifQ.c7gL0q6k-h2m2dZ-v8e0aV7yU8y4dDq79x731-0u0bX27-j3M4` (User role)

**Modified JWT (attacker changes "user" to "admin"):** `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwicm9sZSI6ImFkbWluIn0.jE-yE9c0_d8u53m5xU5i3O0W27XvJ-A-kU4s6X2n74-Z327` (Admin role)


## How to Test

### Using curl

This example assumes a vulnerable endpoint `/protected` requiring authentication with a JWT in the `Authorization` header.  We replace the original token with the modified one:

```bash
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwicm9sZSI6ImFkbWluIn0.jE-yE9c0_d8u53m5xU5i3O0W27XvJ-A-kU4s6X2n74-Z327" https://vulnerable-app.com/protected
```

### Using Burp Suite

1. Intercept the request containing the authentication token.
2. Go to the "Repeater" tab in Burp Suite.
3. Modify the token value (e.g., change the role claim in a JWT).
4. Forward the modified request.
5. Observe the application's response.  If the modified token is accepted, a vulnerability exists.


### Manual Testing

1. Use your browser's developer tools (usually F12) to inspect the network requests.
2. Locate the request containing the authentication token (often in cookies or headers).
3. Identify the token's structure and try to modify it (e.g., change a value, extend the expiry time, etc.).
4. Observe the application's response.  Successful manipulation indicates a vulnerability.

## Security Implications

- **Bypasses authentication mechanisms:** Token manipulation directly bypasses the intended authentication flow.
- **Data breaches:** Attackers can access sensitive user data or manipulate it.
- **Account takeover:** Complete control over user accounts can be achieved.
- **Privilege escalation:**  Attackers might elevate their privileges to access functionalities they shouldn't.
- **Session hijacking:**  Attackers can take control of a user's session.

## Recommendations for Defenders

- **Robust token validation:** Validate all claims in the token, including expiry times and roles.  Don't trust the client-side.
- **Secure token generation:** Use cryptographically secure random number generators and avoid predictable patterns.
- **Proper token expiry:** Implement short token lifetimes and refresh tokens appropriately.
- **Secure token storage:** Avoid storing tokens in easily accessible locations like localStorage or sessionStorage. Use HttpOnly cookies for session tokens.
- **HTTPS:** Always use HTTPS to protect tokens during transmission.
- **Implement CSRF protection:** Use CSRF tokens or other mechanisms to prevent CSRF attacks.
- **Input validation:** Sanitize and validate all user inputs, including those that might indirectly affect token handling.
- **WAF/security tool configurations:** Configure your WAF to detect unusual token manipulation patterns.
- **Regular security audits:** Conduct regular security audits and penetration testing to identify and address vulnerabilities.

## Related Techniques

- Session Hijacking
- Cross-Site Request Forgery (CSRF)
- Cross-Site Scripting (XSS)
- Broken Authentication


## References

- [OWASP Authentication Cheat Sheet](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017_A10_Authentication_and_Session_Management)
- [JWT Security Best Practices](https://jwt.io/introduction/)  (Adapt based on specific JWT library used)
- Relevant CVEs (search for "JWT vulnerability" or similar terms on the National Vulnerability Database)


