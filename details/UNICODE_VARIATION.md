# UNICODE_VARIATION Bypass Technique

## Overview

Unicode Variation Selectors (VS) allow for different visual representations of the same Unicode character.  This technique exploits the fact that some web applications perform insufficient input validation, allowing attackers to bypass input filters designed to block malicious characters or strings by using their visually identical, but technically different, Unicode variations.  The application may see a seemingly harmless character while the underlying code contains malicious intent.


## Technical Details

- **Method**: Input Validation Bypass
- **Vulnerability**: Insufficient Input Validation, lack of proper Unicode normalization, reliance on visual character comparison instead of codepoint comparison.
- **Impact**: Cross-site scripting (XSS), SQL injection, command injection, file path traversal, and other injection attacks.
- **Common Targets**: Web applications with input fields that lack robust sanitization and validation, particularly those that rely on string comparisons instead of codepoint comparisons.


## Example

Let's say a web application has a filter that blocks the `<` character to prevent XSS.  An attacker could use the Unicode variation selector `U+FE68` to represent `<` visually:

`%EF%BF%BD` (This is the UTF-8 encoding of the  combining character U+FE68).  Combined with `<`, this produces a visually identical `<` but may bypass a filter checking for just `<` alone in its ASCII form.  The payload could look like:  `%EF%BF%BD<script>alert(1)</script>`


## How to Test

### Using curl

```bash
curl -H "X-Custom-Header: %EF%BF%BD<script>alert(1)</script>" "http://vulnerable-website.com/page"
```
Replace `%EF%BF%BD` with the relevant UTF-8 encoding of the Unicode variation selector(s) you are testing,  and  `http://vulnerable-website.com/page` with the target URL.  You'll need to experiment with various Unicode variation selectors and their encodings.


### Using Burp Suite

1. Intercept the request to the vulnerable web application.
2. Go to the request's payload.
3. Modify the input field with your payload incorporating Unicode variation selectors.  For example, replace `<` with  `%EF%BF%BD<`.
4. Forward the modified request.
5. Observe the response for any indication of successful exploitation (e.g., an alert box in case of XSS).


### Manual Testing

1. Open the browser's developer tools (usually by pressing F12).
2. Identify an input field on the target web application.
3. Manually type the Unicode variation selector (you might need to use a Unicode editor to input these characters correctly).
4. Submit the form.
5. Observe the application's response for signs of a successful exploit.  You may need to inspect the network traffic in the browser's developer tools to fully see what is being sent to the server.



## Security Implications

- **Bypasses:**  This technique bypasses input filters that rely on simple string comparisons or lack proper Unicode normalization. It circumvents security controls that assume a one-to-one mapping between visual representation and character codepoint.
- **Potential Risks:** This can lead to severe security breaches, including XSS attacks enabling session hijacking, data theft, and website defacement.  SQL injection using this bypass can result in database compromise.
- **Real-world attack scenarios:**  Attackers could use this technique to inject malicious scripts into forms, comments sections, or other user-submitted content, potentially taking over user accounts or manipulating data.



## Recommendations for Defenders

- **Detection:** Implement robust input validation that performs character codepoint comparison rather than relying on visual representation. Utilize Unicode normalization (NFC or NFD) consistently before validation.
- **Mitigation Strategies:** Employ a secure input validation library that handles Unicode characters appropriately.  Escape or encode all user input before displaying it on the page.
- **Secure Coding Practices:** Avoid using string comparison alone for security-sensitive input validation. Always normalize input to a canonical form.
- **WAF/security tool configurations:** Configure your Web Application Firewall (WAF) to detect and block requests containing suspicious Unicode sequences, especially those commonly associated with known exploit vectors.


## Related Techniques

- Homograph Attack
- IDN Homograph Attack
- Byte-Level Encoding


## References

- OWASP Input Validation Cheat Sheet
- OWASP Top Ten
- [Relevant CVE entries will vary depending on specific implementation and context]

- [Insert links to relevant blog posts and research papers on Unicode and web application security]


