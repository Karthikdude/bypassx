# REQUEST_SMUGGLING_TE_CL Bypass Technique

## Overview

REQUEST_SMUGGLING_TE_CL is a request smuggling technique that exploits the interaction between a client's `Transfer-Encoding: chunked` header and a server's handling of HTTP requests.  It leverages the ambiguity in how some servers interpret chunked encoding combined with a carefully crafted `Content-Length` header in a subsequent request. This allows an attacker to smuggle malicious requests behind a legitimate request, potentially leading to arbitrary code execution or data manipulation on the target server.  The "CL" suffix indicates the use of a `Content-Length` header in the attack.

## Technical Details

- **Method**: HTTP Headers Manipulation
- **Vulnerability**: Improper handling of HTTP requests with `Transfer-Encoding: chunked` and `Content-Length` headers. Specifically, vulnerable servers fail to properly validate the consistency between these headers leading to misinterpretation of request boundaries.
- **Impact**:  Successful exploitation can lead to various attacks including:
    - Arbitrary code execution (if the server processes smuggled requests as part of its backend logic).
    - Session hijacking (by smuggling a session manipulation request).
    - Data exfiltration (by smuggling a request that reads sensitive data).
    - Server-side request forgery (SSRF) attacks.
- **Common Targets**: Web servers and application servers that improperly handle HTTP/1.1 chunked transfer encoding and the `Content-Length` header simultaneously, especially those lacking robust request parsing and validation.


## Example

Let's say we have a legitimate request:

```http
POST /some/page HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
Content-Type: application/x-www-form-urlencoded

5
hello
0
```

A malicious smuggled request could look like this:

```http
POST /evil/page HTTP/1.1
Host: example.com
Content-Length: 11

world
```

The server, if vulnerable, might interpret the "world" part as belonging to the second request, due to a flawed implementation regarding the `Content-Length` and the already processed `Transfer-Encoding: chunked` part of the first request.


## How to Test

### Using curl

This example requires crafting a multipart request with appropriate headers.  This is difficult to achieve directly with `curl`, and often requires tools like `pwgen` to help generate the chunked data:


```bash
#This is a simplified example and will likely not work without adjustments based on the target's specific vulnerability.  
#You need to carefully craft the chunked body and the subsequent content-length header to exploit.

#Generate the chunked data. This might need alteration depending on the target's specific requirements:
CHUNKED_DATA=$(pwgen -c 10 10)
CONTENT_LENGTH=$(echo -n "POST /vulnerable/page HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n" | wc -c)
curl -X POST -H "Transfer-Encoding: chunked" -H "Content-Type: application/x-www-form-urlencoded" -d "$CHUNKED_DATA"  -H "Content-Length: $CONTENT_LENGTH" "http://example.com/page"
```

### Using Burp Suite

1. **Intercept the legitimate request:** Set Burp Suite to intercept HTTP traffic. Make a request to the target application.
2. **Modify the request:**  Add a `Transfer-Encoding: chunked` header to the request and add a valid chunked body.
3. **Add the malicious request:**  After the chunked data, insert a new HTTP request with a `Content-Length` header specifying the length of the following malicious data.  This data will be your second request that will be smuggled.
4. **Forward the request:** Forward the modified request to the server. Monitor the server's response for any indications of successful smuggling.


### Manual Testing

Manual testing is challenging due to the complexities involved in crafting correctly formatted chunked requests. Using Burp Suite is highly recommended for practical testing.


## Security Implications

- **Bypass of security controls:** This bypasses traditional input validation mechanisms that might not check the integrity between `Transfer-Encoding` and `Content-Length` headers.
- **Potential risks and impacts:**  Unrestricted access to sensitive data, system compromise, and data breaches.
- **Real-world attack scenarios:**  An attacker could smuggle a request to execute arbitrary code, steal session cookies, or exfiltrate confidential data.


## Recommendations for Defenders

- **Detect this bypass attempt:** Implement robust HTTP request parsing and validation that checks for consistency between headers like `Transfer-Encoding` and `Content-Length`.  Log unusual header combinations for auditing.
- **Mitigation strategies:**  Strictly enforce a single transfer encoding method (avoid supporting both `Transfer-Encoding: chunked` and `Content-Length`).  Reject requests with inconsistent header values.  Implement proper request boundary checks.
- **Secure coding practices:**  Validate all HTTP headers thoroughly. Sanitize and escape all user inputs.
- **WAF/security tool configurations:**  Configure WAF rules to detect and block suspicious header combinations.  Update WAF signatures regularly.


## Related Techniques

- HTTP Request Smuggling (various other techniques)
- HTTP Header Injection


## References

- [Relevant Blog Posts/Research Papers](Insert links here -  search for "HTTP Request Smuggling" and "chunked encoding vulnerabilities")
- [Potential CVE Entries] (Search for relevant CVEs related to request smuggling vulnerabilities)
- [Tools implementing this bypass] (Potentially mention Burp Suite, and other penetration testing tools that might assist in testing)

**Disclaimer:** This documentation is for educational purposes only.  The use of this information for illegal activities is strictly prohibited.  Always obtain explicit permission before testing these techniques on any system.
