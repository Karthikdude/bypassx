# JWT_NONE_ALGORITHM Bypass Technique

## Overview

This technique exploits a vulnerability in applications that use JSON Web Tokens (JWTs) and allow the `none` algorithm for signing.  A JWT with the `none` algorithm signifies that no signature is used, making the token easily forgeable.  An attacker can create valid-looking JWTs without needing the secret key, effectively bypassing authentication and authorization mechanisms.

## Technical Details

- **Method**: JWT Manipulation
- **Vulnerability**: Improper JWT algorithm configuration (allowing `alg: none`)
- **Impact**: Complete authentication bypass, allowing attackers to impersonate any user or access restricted resources.  Data breaches, account takeovers, and privilege escalation are possible.
- **Common Targets**: Web applications using JWTs for authentication and authorization that have not properly configured the allowed algorithms.

## Example

Let's assume a vulnerable application uses a JWT with the following structure:

```json
{
  "header": {
    "alg": "none",
    "typ": "JWT"
  },
  "payload": {
    "user": "admin",
    "roles": ["admin"]
  },
  "signature": "" 
}
```

An attacker can easily modify the `payload` to impersonate the admin user without needing to generate a signature because the algorithm is set to `none`.  The application will accept this modified JWT because it doesn't verify a signature.

The complete JWT (without a signature) would look like this (encoded):

```text
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlcyI6WyJhZG1pbiJdfQ.
```

## How to Test

### Using curl

```bash
curl -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlcyI6WyJhZG1pbiJdfQ." <target_url>
```
Replace `<target_url>` with the vulnerable application endpoint.  This command sends a forged JWT with the `none` algorithm in the Authorization header.


### Using Burp Suite

1. Intercept a legitimate JWT request.
2. Modify the JWT header to change the `alg` to `"none"` and remove the signature.  Ensure the payload contains the desired user privileges.
3. Forward the modified request.


### Manual Testing

1. Use your browser's developer tools (usually F12) to intercept a JWT request.
2.  Modify the JWT header to set `alg` to `"none"` and remove the signature.  Change the payload to reflect the desired user or privileges.
3. Resend the modified request.  If successful, the application will accept the forged JWT.


## Security Implications

- **Bypasses signature verification:** This bypasses the core security mechanism of JWTs – signature verification.
- **Unauthorized access:** Attackers gain unauthorized access to sensitive data and functionalities.
- **Account takeover:**  Attackers can impersonate users, potentially leading to data breaches and financial losses.
- **Privilege escalation:** Attackers can elevate their privileges to gain higher-level access.
- **Data exfiltration:** Attackers may exfiltrate sensitive data.


## Recommendations for Defenders

- **Never allow `none` algorithm:** Strictly prohibit the `none` algorithm in your JWT configuration.  Always use a strong signing algorithm like HS256, RS256, or ES256.
- **Input validation:** Validate the `alg` header on the received JWT and reject tokens with `alg: none`.
- **Regular security audits:** Conduct regular security assessments and penetration testing to identify vulnerabilities.
- **Secure coding practices:** Follow secure coding guidelines when implementing JWT authentication.
- **WAF/security tool configurations:** Configure your WAF to block requests containing JWTs with `alg: none`.
- **Implement robust logging and monitoring:**  Monitor for suspicious JWT usage patterns.


## Related Techniques

- JWT signature forgery (using different algorithms)
- JWT payload manipulation (if not properly validated)
- Session hijacking

## References

- [OWASP API Security Top 10](https://owasp.org/www-project-top-ten/)
- [JWT specification](https://jwt.io/)
- [Various blog posts on JWT vulnerabilities](Search for "JWT vulnerabilities" on Google)


**Note:** This documentation is for educational purposes only.  Using this information for malicious activities is illegal and unethical.  Always obtain explicit permission before testing security vulnerabilities on any system.
