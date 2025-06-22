# AWS_ALB_BYPASS Technique

## Overview

This technique exploits misconfigurations in AWS Application Load Balancers (ALBs) to bypass intended security controls, such as WAF rules or authentication mechanisms.  It leverages the ALB's routing behavior and potentially vulnerabilities in its interaction with backend resources to access unauthorized functionalities or data. This is often achieved by manipulating the HTTP request in ways not properly handled by the ALB's configuration or by exploiting weaknesses in how the ALB interacts with other AWS services.

## Technical Details

- **Method**: Primarily HTTP Header Manipulation, URL Manipulation, and potentially exploiting misconfigured backend services.
- **Vulnerability**: Misconfiguration of AWS Application Load Balancers (ALB), including improper rule sets, insufficient authentication enforcement, or flawed access control lists (ACLs) at the ALB or backend level.  It can also involve vulnerabilities in the backend services themselves.
- **Impact**: Unauthorized access to web applications, data breaches, server compromise, denial of service, and complete application takeover.
- **Common Targets**: Web applications protected by AWS ALBs with improperly configured security rules, lacking robust authentication, or exhibiting vulnerabilities in the underlying infrastructure or backend services.


## Example

Let's assume a vulnerable application uses an ALB to route traffic based on the `Host` header.  A misconfiguration might allow requests with unexpected `Host` headers to bypass intended access restrictions.

**Scenario:**  The application is intended to be accessible only via `myapp.example.com`. However, the ALB's configuration doesn't properly validate the `Host` header.

**Bypass:**  Sending a request to the ALB's IP address with a manipulated `Host` header (`Host: internal-service.example.com`) might route the request to an internal service not meant to be publicly accessible, potentially revealing sensitive information or allowing unauthorized access.

## How to Test

### Using curl

```bash
curl -H "Host: internal-service.example.com" <ALB_IP_ADDRESS>/path/to/resource
```
Replace `<ALB_IP_ADDRESS>` with the actual IP address of the ALB and `/path/to/resource` with the target path.  This example manipulates the `Host` header.  Other headers may need to be manipulated depending on the specific misconfiguration.


### Using Burp Suite

1. Proxy your traffic through Burp Suite.
2. Access the ALB protected application through your browser.
3. Identify the request headers and the response.
4. Manually modify the request headers (e.g., `Host`, `X-Forwarded-For`, `X-Forwarded-Proto`) to test different values and observe the response. 
5. Try manipulating the URL path to discover unintended endpoints or bypass authorization mechanisms.
6. Analyze the responses for potential indications of bypass (e.g., unexpected data, different authentication mechanisms engaged, access to unauthorized resources).


### Manual Testing

1. Access the ALB's IP address directly in your browser. This might reveal unexpected responses or access points.
2. Attempt to access resources using different paths and manipulated URL parameters to identify potential misconfigurations.
3. Examine the browser's developer tools (Network tab) to analyze HTTP requests and responses.  Look for clues in the headers or the response bodies indicating vulnerabilities.


## Security Implications

- **Bypasses:** This bypasses WAF rules, authentication mechanisms, and access control lists configured at the ALB or backend level.
- **Risks:** Data breaches, server compromise, application takeover, unauthorized access to sensitive information, and denial-of-service attacks.
- **Real-world scenarios:** An attacker could gain access to internal APIs, databases, or configuration files, leading to a significant compromise.


## Recommendations for Defenders

- **Detection:** Regularly audit ALB configurations, including access logs and security group rules. Implement robust logging and monitoring to detect unusual requests or access patterns. Employ intrusion detection/prevention systems (IDS/IPS) capable of analyzing ALB traffic.
- **Mitigation:** Properly configure ALB access control lists (ACLs), security groups, and WAF rules.  Validate all incoming headers and parameters rigorously. Implement strong authentication and authorization mechanisms.  Regularly review and update security configurations. Segment your network architecture to isolate internal services.  Utilize principle of least privilege.
- **Secure coding practices:** Validate all user inputs thoroughly on the backend. Avoid relying solely on client-side validation.
- **WAF/security tool configurations:** Configure your WAF to block or flag suspicious requests, including those with manipulated headers. Use a robust web application firewall (WAF) that can be fine-tuned to address specific risks.


## Related Techniques

- Header Injection
- Path Traversal
- Parameter Tampering
- Server-Side Request Forgery (SSRF)


## References

- [AWS Application Load Balancer Documentation](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/introduction.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) (various related vulnerabilities)


This documentation provides a general overview.  Specific bypass techniques and mitigation strategies depend heavily on the exact ALB configuration and backend services. Remember to always obtain explicit permission before testing security vulnerabilities on any system.
