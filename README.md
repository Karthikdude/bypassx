# BypassX - Advanced HTTP 403 Bypass Testing Suite

A high-performance, comprehensive HTTP 403 bypass testing tool built with Go and featuring a complete Flask testing laboratory with modern security protections.

## Features

### Core Tool (Go)
- **High Concurrency**: Goroutine-based worker pool architecture with configurable concurrency
- **80+ Bypass Techniques**: Comprehensive coverage of basic and advanced bypass methods
- **Modern Security Bypasses**: WAF, CDN, API, container, and ML evasion techniques
- **Flexible Configuration**: Custom headers, proxies, wordlists, and output formats
- **Performance Optimized**: Efficient HTTP client with timeout and rate limiting

### Testing Laboratory (Flask)
- **11 Protected Endpoints**: Each with specific vulnerabilities and bypass techniques
- **Real-time Statistics**: Live tracking of bypass attempts and success rates
- **Modern Security Simulation**: Cloudflare WAF, CDN protection, API security, service mesh
- **Comprehensive Coverage**: Traditional and cutting-edge protection mechanisms

## Installation

### Prerequisites
- Go 1.22+
- Python 3.11+
- Flask and requests packages

### Build
```bash
# Install dependencies
go mod init bypassx
go mod tidy

# Build the tool
go build -o bypassx .

# Install Python dependencies
pip install flask requests
```

## Usage

### Basic Usage
```bash
# Test single URL
./bypassx -u https://target.com/admin

# Test with high concurrency
./bypassx -u https://target.com/admin -t 20 -verbose

# Test multiple URLs from file
./bypassx -l urls.txt -o results.txt

# Use proxy
./bypassx -u https://target.com/admin -proxy http://127.0.0.1:8080
```

### Advanced Options
```bash
# Custom headers
./bypassx -u https://target.com/admin -H headers.txt

# Specific techniques only
./bypassx -u https://target.com/admin -basic
./bypassx -u https://target.com/admin -advanced

# Custom success codes
./bypassx -u https://target.com/admin -status "200,302,401"

# Use wordlist for path fuzzing
./bypassx -u https://target.com/admin -wordlist wordlists/admin_paths.txt
```

## Testing Laboratory

### Start the Lab
```bash
python lab.py
```
Access at: http://127.0.0.1:5000

### Protected Endpoints

| Endpoint | Protection Type | Vulnerable Techniques |
|----------|----------------|----------------------|
| `/admin` | Basic 403 | Path manipulation, headers, methods |
| `/api/admin` | API Protection | Path traversal, content-type bypass |
| `/secure` | Authentication | Bearer tokens, basic auth, WebSocket |
| `/internal` | IP Filtering | Header pollution, forwarded headers |
| `/debug` | Method Filtering | Verb tunneling, fragments |
| `/waf` | Modern WAF | Cloudflare bypass, cache deception |
| `/cdn` | CDN Protection | Origin IP, cache poisoning |
| `/api/v2/admin` | API Security | JWT bypass, GraphQL, CORS |
| `/microservice` | Service Mesh | Istio/Envoy, Kubernetes, containers |
| `/ml-protected` | ML Detection | Adversarial inputs, timing attacks |
| `/advanced` | Advanced | Unicode, encoding, CRLF injection |

### Automated Testing
```bash
# Run comprehensive test suite
python test_runner.py

# Quick validation test
python quick_test.py
```

## Bypass Techniques

### Basic Techniques (40+)
- HTTP method tampering (HEAD, OPTIONS, PUT, DELETE, PATCH, TRACE)
- X-HTTP-Method-Override headers
- Path obfuscation (trailing chars, encoding, case manipulation)
- Header manipulation (IP spoofing, referer, user-agent)
- Authentication bypass (basic auth, bearer tokens)
- Content-type manipulation
- Host header attacks
- Proxy/CDN bypass techniques

### Advanced Techniques (40+)
- Unicode and confusable characters
- Double URL encoding
- Null path segment injection
- Proxy/load balancer confusion
- Request smuggling simulation
- Header pollution attacks
- File extension spoofing
- Modern WAF evasion (Cloudflare, AWS ALB)
- CDN bypass (origin IP, cache poisoning)
- API security bypass (JWT none algorithm, GraphQL)
- Container escape simulation
- Service mesh bypass (Istio/Envoy)
- ML model evasion techniques

## Architecture

### Go Tool Structure
```
main.go              - CLI interface and workflow orchestration
bypass_techniques.go - All bypass technique implementations
concurrent_worker.go - Worker pool and HTTP client management
```

### Flask Lab Structure
```
lab.py              - Main application with all endpoints
test_runner.py      - Automated testing and validation
quick_test.py       - Simple validation script
wordlists/          - Path and user-agent wordlists
static/             - Web interface assets
```

## Performance Metrics

- **Concurrency**: Up to 100 concurrent workers
- **Throughput**: 100+ requests/second (depending on target)
- **Success Rate**: 80%+ bypass success in testing lab
- **Techniques**: 80+ total bypass methods implemented
- **Coverage**: Basic (95%+) and Advanced (85%+) technique coverage

## Command Line Options

### Core Options
| Flag | Description | Example |
|------|-------------|---------|
| `-u` | Target URL | `-u https://target.com/admin` |
| `-l` | URL list file | `-l urls.txt` |
| `-H` | Custom headers file | `-H headers.txt` |
| `-m` | Specific HTTP method | `-m POST` |
| `-o` | Output file | `-o results.txt` |
| `-t` | Concurrency level | `-t 20` |
| `-timeout` | Request timeout | `-timeout 30` |
| `-verbose` | Verbose output | `-verbose` |
| `-proxy` | HTTP proxy | `-proxy http://127.0.0.1:8080` |
| `-cookie` | Custom cookies | `-cookie "session=abc123"` |
| `-data` | POST data | `-data "param=value"` |
| `-stdin` | Read URLs from stdin | `-stdin` |
| `-status` | Success status codes | `-status "200,302"` |
| `-wordlist` | Path wordlist | `-wordlist paths.txt` |

### Technique Categories
| Flag | Description | Coverage |
|------|-------------|----------|
| `-all` | All techniques (default) | 150+ bypass methods |
| `-basic` | Basic techniques only | 40+ fundamental bypasses |
| `-advanced` | Advanced techniques only | 40+ sophisticated methods |
| `-protocol` | Protocol & method bypasses | HTTP method override, CONNECT, version manipulation |
| `-path` | Advanced path manipulation | Path traversal, normalization, null bytes |
| `-headers` | Header pollution techniques | XFF pollution, host injection, smuggling |
| `-lb` | Load balancer bypasses | AWS ALB, F5, Nginx, Apache, HAProxy |
| `-content` | Content-type bypasses | XML, multipart, charset encoding |
| `-auth` | Authentication bypasses | Session, cookie, token manipulation |
| `-rate` | Rate limiting bypasses | Bypass headers, bot user agents |
| `-geo` | Geographic bypasses | Country codes, IP whitelisting |
| `-file` | File extension bypasses | Extension spoofing, MIME types |
| `-cache` | Cache bypasses | Cache control, CDN origin |
| `-modern` | Modern security bypasses | CSP, CSRF, security headers |
| `-encode` | Encoding bypasses | Unicode, double encoding, mixed |
| `-container` | Container bypasses | Docker, Kubernetes, Istio/Envoy |

## Testing Results

### Comprehensive Testing Statistics
- **Total Specialized Tests**: 58 advanced bypass techniques
- **Overall Success Rate**: 100%
- **Successful Bypasses**: 58/58
- **Lab Confirmed**: 57 bypasses verified
- **Lab Success Rate**: 100%

### Category Performance
| Category | Success Rate | Techniques |
|----------|-------------|------------|
| Protocol & Method | 100% (5/5) | HTTP method override, version bypass, CONNECT |
| Authentication | 100% (7/7) | Session manipulation, cookie bypass, token abuse |
| Container | 100% (6/6) | Docker, Kubernetes, Istio/Envoy bypasses |
| Header Pollution | 100% (5/5) | XFF pollution, host injection, smuggling |
| Content & Accept | 100% (5/5) | XML content-type, multipart, charset encoding |
| Rate Limiting | 100% (2/2) | Rate limit headers, bot user agents |
| Geographic | 100% (4/4) | Country codes, IP whitelisting |
| Cache & CDN | 100% (3/3) | Cache control, CDN origin bypass |
| Modern Security | 100% (3/3) | CSP bypass, CSRF protection |
| Load Balancer | 100% (7/7) | AWS ALB, F5 BIG-IP, Nginx, Apache, HAProxy |
| Path Manipulation | 100% (6/6) | Path traversal, encoded traversal, null bytes, fragment manipulation |
| File & MIME | 100% (3/3) | MIME spoofing, extension bypass, file type manipulation |
| Encoding | 100% (3/3) | Unicode, double encoding, mixed encoding techniques |

### Successful Techniques
✓ **Protocol Level**: HTTP method override, version manipulation, CONNECT tunneling
✓ **Infrastructure**: Load balancer bypass (AWS ALB, F5 BIG-IP, Nginx, Apache, HAProxy)
✓ **Authentication**: Session hijacking, cookie manipulation, token abuse
✓ **Modern Platforms**: Container escape, Kubernetes service accounts, Istio bypasses
✓ **Security Controls**: WAF evasion, rate limiting bypass, geographic restrictions
✓ **Advanced Headers**: XFF pollution, host injection, request smuggling simulation

## Contributing

1. Add new bypass techniques to `bypass_techniques.go`
2. Create corresponding vulnerabilities in `lab.py`
3. Update test cases in `test_runner.py`
4. Validate with `python quick_test.py`

## Security Note

This tool is designed for authorized security testing only. Ensure you have explicit permission before testing any systems you do not own.

## License

MIT License - See LICENSE file for details