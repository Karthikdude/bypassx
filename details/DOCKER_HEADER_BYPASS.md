# DOCKER_HEADER_BYPASS Technique

## Overview

The DOCKER_HEADER_BYPASS technique exploits weaknesses in web applications that rely solely on HTTP headers, specifically the `Docker-Client` or similar custom headers, to identify and restrict access to internal Docker services or sensitive information exposed via Docker containers.  This bypass leverages the fact that these headers can be easily forged or manipulated by an attacker, bypassing intended access controls.

## Technical Details

- **Method**: HTTP Header Manipulation
- **Vulnerability**: Insufficient input validation and authorization relying solely on HTTP headers for access control.  Specifically, this targets applications that trust the `Docker-Client` header (or similar custom headers) without verifying the actual origin or legitimacy of the request.
- **Impact**: Unauthorized access to internal Docker APIs, sensitive data within Docker containers, or potentially even control over exposed Docker services, leading to data breaches, server compromises, or complete system takeover.
- **Common Targets**: Web applications exposing Docker APIs or other internal services via reverse proxies or load balancers without proper authentication and authorization mechanisms beyond header checks.  Applications mistakenly relying on headers originating from a Docker client for authentication are particularly vulnerable.


## Example

Let's assume a vulnerable web application exposes a Docker API endpoint at `/docker-api` and only allows requests with a `Docker-Client: MyTrustedDockerClient` header.

A legitimate request would look like this:

```
curl -H "Docker-Client: MyTrustedDockerClient" http://vulnerable-app.com/docker-api
```

The bypass would involve simply forging the header, even from a non-Docker client:

```
curl -H "Docker-Client: MyTrustedDockerClient" http://vulnerable-app.com/docker-api
```

The application, failing to verify the header's authenticity, would grant access.

## How to Test

### Using curl

```bash
curl -H "Docker-Client:MaliciousClient" -X GET "http://target-url/docker-api"
```
Replace `"MaliciousClient"` and `"http://target-url/docker-api"` with the appropriate values.  Experiment with different header values and HTTP methods.

### Using Burp Suite

1. Intercept a request to the suspected vulnerable endpoint in Burp Suite.
2. Go to the "Headers" tab.
3. Add or modify a header named `Docker-Client` (or a similar custom header used by the application) with a forged value.
4. Forward the modified request.
5. Observe the response to check for unauthorized access.

### Manual Testing

1. Use your browser's developer tools (usually accessible via F12).
2. Navigate to the vulnerable endpoint.
3. In the Network tab, find the request to the endpoint.
4. Modify the request headers to add or change the `Docker-Client` (or similar) header.
5. Send the modified request.


## Security Implications

- **Bypasses Authentication:** This technique directly bypasses any authentication or authorization relying exclusively on the presence or value of the `Docker-Client` header.
- **Data Breaches:**  Attackers can access sensitive data exposed via Docker containers.
- **Server Compromise:** Attackers could potentially exploit vulnerabilities within exposed Docker APIs to gain complete control over the server.
- **Denial of Service:**  In some scenarios, a large number of forged requests could overwhelm the application, leading to a denial-of-service attack.


## Recommendations for Defenders

- **Strong Authentication:** Implement robust authentication mechanisms beyond HTTP header checks. Use OAuth 2.0, JWT, or other secure authentication protocols.
- **Input Validation:** Validate all incoming requests, including headers, to verify their origin and authenticity.
- **Authorization:** Implement granular authorization controls to restrict access based on user roles and permissions.
- **Least Privilege:**  Run Docker containers with the principle of least privilege. Only grant containers the minimum necessary permissions.
- **Network Segmentation:** Isolate Docker containers and their associated APIs from the public internet.
- **WAF Configuration:** Configure your WAF to block or flag requests with forged or suspicious `Docker-Client` headers.  Implement custom rules for specific header values.
- **Regular Security Audits:** Regularly audit your web applications and Docker environments for vulnerabilities.


## Related Techniques

- HTTP Header Injection
- API Key Bruteforcing
- Session Hijacking


## References

- [Insert relevant CVE numbers if applicable]
- [Link to relevant blog posts or research papers on header manipulation vulnerabilities]
- [Link to security tools that can detect forged headers (e.g., some WAFs)]
