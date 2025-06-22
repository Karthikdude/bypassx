# UNICODE_NORMALIZATION Bypass Technique

## Overview

Unicode normalization exploits the fact that Unicode characters can have multiple equivalent representations.  Different normalization forms (NFC, NFD, NFKC, NFKD) represent the same character differently.  Applications that don't properly handle these normalization forms can be vulnerable to bypass techniques where a malicious string, when normalized differently, is accepted while its equivalent representation in a different normalization form is rejected by security controls.  This allows attackers to bypass input validation, authentication mechanisms, or other security filters that are not normalization-aware.

## Technical Details

- **Method**: Input Validation Bypass, Character Encoding Manipulation
- **Vulnerability**: Insufficient Input Validation, Lack of Unicode Normalization Handling, reliance on string comparison without normalization
- **Impact**: Unauthorized access, data manipulation, cross-site scripting (XSS), SQL injection, account takeover.
- **Common Targets**: Web applications with input validation relying on simple string comparisons (e.g., blacklist/whitelist approaches), authentication systems using username/password fields, applications with vulnerable search functionalities.

## Example

Let's consider a simple example where a web application filters out the string "evil.com" to prevent domain spoofing in email addresses.

* **Malicious Input (NFD):** `e\u0301vil.com` (e with acute accent decomposed)
* **Normalized to NFC:** `evil.com` (composed form)

An application that only checks for "evil.com" in its normalized NFC form might allow `e\u0301vil.com` because it doesn't explicitly check for different Unicode normalization forms.  The NFD form passes the validation but normalizes to the blocked string.

## How to Test

### Using curl

```bash
curl -H "X-Custom-Header: e\u0301vil.com" <target_url>
```

This sends a header with the NFD normalized "evil.com".  Replace `<target_url>` with the target URL and adjust the header name accordingly.


### Using Burp Suite

1. Intercept a request to the vulnerable application.
2. Identify the input field susceptible to the bypass.
3. Modify the input field value by inserting a Unicode character in its decomposed form (NFD). For example, instead of "test", use "t\u0306est" (t with a circumflex accent decomposed).
4. Send the modified request.
5. Observe whether the application processes the modified input differently than the original input.


### Manual Testing

1. Find a vulnerable input field (e.g., username, email).
2. Enter a string that should trigger a security mechanism (e.g., blocked keyword).
3. Convert some characters of the string to their NFD form using a Unicode normalization tool or online converter.
4. Test if the modified string bypasses the security check.


## Security Implications

- **Bypasses input validation:** This technique bypasses security checks relying on simple string comparison without considering Unicode normalization.
- **Potential for various attacks:**  Successful exploitation opens the door to XSS, SQL injection, and authentication bypass.
- **Real-world attack scenarios:** Attackers can use this to create malicious accounts, inject scripts, or exfiltrate data.


## Recommendations for Defenders

- **Detect:** Implement robust input validation that checks for all Unicode normalization forms (NFC, NFD, NFKC, NFKD) before processing user input.
- **Mitigate:**  Normalize all user inputs to a consistent form (e.g., NFC) before performing any security checks or database operations.
- **Secure coding practices:** Avoid relying on simple string comparisons. Use parameterized queries (for SQL) and proper escaping/encoding techniques (for XSS).
- **WAF/security tool configurations:** Configure WAFs to detect and block requests containing potential Unicode normalization bypass attempts based on normalization form differences.


## Related Techniques

- Case-insensitive bypasses
- Homograph attacks
- IDN homograph attacks
- Encoding bypasses (e.g., URL encoding, double encoding)


## References

- [OWASP Input Validation Cheat Sheet](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017_A5_Broken_Access_Control) (Related to Input Validation)
- [Unicode Normalization Forms](https://unicode.org/reports/tr15/)
- [Various blog posts and security advisories on Unicode normalization bypasses (search for relevant keywords on security websites)]

(Note: Specific CVE entries related to Unicode normalization bypasses are less common as a standalone vulnerability, but often part of broader input validation flaws.)
