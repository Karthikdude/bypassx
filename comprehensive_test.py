#!/usr/bin/env python3
"""
Comprehensive test for all new specialized bypass endpoints
"""

import requests
import json
import time

LAB_URL = "http://127.0.0.1:5000"

def test_bypass(endpoint, headers=None, method="GET", data=None):
    """Test a specific bypass technique"""
    url = f"{LAB_URL}{endpoint}"
    try:
        if method == "POST":
            response = requests.post(url, headers=headers, json=data, timeout=5)
        else:
            response = requests.request(method, url, headers=headers, timeout=5)
        
        return {
            'url': url,
            'status': response.status_code,
            'success': response.status_code == 200,
            'response': response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text[:100]
        }
    except Exception as e:
        return {
            'url': url,
            'status': 0,
            'success': False,
            'error': str(e)
        }

def run_specialized_tests():
    """Test all new specialized bypass endpoints"""
    print("BypassX Specialized Endpoints Testing")
    print("="*60)
    
    # Comprehensive test cases for new endpoints
    test_cases = [
        # Protocol & Method Bypasses
        ("Method Override X-HTTP", "/method-override", {"X-HTTP-Method": "GET"}, "POST", None),
        ("Method Override X-Method", "/method-override", {"X-Method-Override": "GET"}, "POST", None),
        ("Method Override Param", "/method-override?_method=GET", None, "GET", None),
        ("HTTP Version Settings", "/http-version", {"HTTP2-Settings": "AAMAAABkAARAAAAAAAIAAAAA"}, "GET", None),
        ("Connect Header", "/connect-method", {"X-HTTP-Method": "CONNECT"}, "GET", None),
        
        # Advanced Path Manipulation
        ("Path Traversal", "/path-normalization/../", None, "GET", None),
        ("Path Dot Slash", "/path-normalization/./", None, "GET", None),
        ("Encoded Traversal", "/path-normalization%2e%2e/", None, "GET", None),
        ("Null Byte", "/null-bytes%00", None, "GET", None),
        ("Semicolon Params", "/path-params;jsessionid=123", None, "GET", None),
        ("Fragment", "/fragment-bypass?fragment=test", None, "GET", None),
        
        # Header Pollution & Smuggling
        ("XFF Pollution", "/header-pollution", {"X-Forwarded-For": "evil.com, 127.0.0.1"}, "GET", None),
        ("XFF Multiple IPs", "/xff-pollution", {"X-Forwarded-For": "1.1.1.1, 2.2.2.2, 127.0.0.1"}, "GET", None),
        ("Host Injection", "/host-injection", {"Host": "internal"}, "GET", None),
        ("Host Port", "/host-injection", {"Host": "localhost:80"}, "GET", None),
        ("CL.TE Smuggling", "/request-smuggling", {"Content-Length": "0", "Transfer-Encoding": "chunked"}, "POST", None),
        
        # Load Balancer Bypasses
        ("AWS ALB", "/lb-bypass", {"X-Amzn-Trace-Id": "Root=1-67890abc"}, "GET", None),
        ("F5 BIG-IP", "/lb-bypass", {"X-F5-Auth-Token": "admin_token_123"}, "GET", None),
        ("Nginx Underscore", "/nginx-bypass", {"X_Forwarded_For": "127.0.0.1"}, "GET", None),
        ("Nginx Accel", "/nginx-bypass", {"X-Accel-Redirect": "/internal/admin"}, "GET", None),
        ("Apache Rewrite", "/apache-bypass", {"X-Original-URL": "/admin"}, "GET", None),
        ("Apache Range", "/apache-bypass", {"Range": "bytes=0-1023"}, "GET", None),
        ("HAProxy State", "/haproxy-bypass", {"X-Haproxy-Server-State": "UP"}, "GET", None),
        
        # Content-Type & Accept
        ("XML Content-Type", "/content-type", {"Content-Type": "text/xml"}, "POST", None),
        ("Multipart", "/content-type", {"Content-Type": "multipart/form-data"}, "POST", None),
        ("Accept XML", "/accept-bypass", {"Accept": "application/xml"}, "GET", None),
        ("Accept Wildcard", "/accept-bypass", {"Accept": "*/*"}, "GET", None),
        ("Charset Encoding", "/charset-bypass", {"Content-Type": "text/html; charset=utf-7"}, "POST", None),
        
        # Authentication Context
        ("Session ID", "/session-bypass", {"X-Session-ID": "admin"}, "GET", None),
        ("User ID Zero", "/session-bypass", {"X-User-ID": "0"}, "GET", None),
        ("Cookie Admin", "/cookie-bypass", {"Cookie": "admin=true"}, "GET", None),
        ("Cookie Role", "/cookie-bypass", {"Cookie": "role=administrator"}, "GET", None),
        ("Token Bearer", "/token-bypass", {"Authorization": "Bearer admin"}, "GET", None),
        ("Token Basic", "/token-bypass", {"Authorization": "Token 12345"}, "GET", None),
        
        # Rate Limiting
        ("Rate Limit Header", "/rate-limit-bypass", {"X-Rate-Limit-Bypass": "true"}, "GET", None),
        ("Bot User Agent", "/rate-limit-bypass", {"User-Agent": "Googlebot/2.1 (+http://www.google.com/bot.html)"}, "GET", None),
        
        # Geographic & IP
        ("Cloudflare Country", "/geo-bypass", {"CF-IPCountry": "US"}, "GET", None),
        ("Country Code", "/geo-bypass", {"X-Country-Code": "US"}, "GET", None),
        ("Client IP", "/ip-whitelist", {"X-Client-IP": "192.168.1.1"}, "GET", None),
        ("Real IP", "/ip-whitelist", {"X-Real-IP": "10.0.0.1"}, "GET", None),
        
        # File Extension & MIME
        ("File Extension TXT", "/extension-bypass.txt", None, "GET", None),
        ("File Extension LOG", "/extension-bypass.log", None, "GET", None),
        ("MIME Spoofing", "/mime-bypass", {"Content-Type": "image/jpeg"}, "POST", None),
        
        # Cache & CDN
        ("Cache Control", "/cache-bypass", {"Cache-Control": "no-cache"}, "GET", None),
        ("Pragma No-Cache", "/cache-bypass", {"Pragma": "no-cache"}, "GET", None),
        ("CDN Origin", "/cdn-origin", {"X-Forwarded-Server": "origin.example.com"}, "GET", None),
        
        # Modern Security
        ("CSP Bypass", "/csp-bypass", {"X-Content-Type-Options": "nosniff"}, "GET", None),
        ("CSRF Token", "/csrf-bypass", {"X-CSRF-Token": "bypass"}, "GET", None),
        ("CSRF AJAX", "/csrf-bypass", {"X-Requested-With": "XMLHttpRequest"}, "GET", None),
        
        # Encoding & Obfuscation
        ("Double Encode", "/double-encode%2525", None, "GET", None),
        ("Mixed Encode", "/mixed-encode%41%61", None, "GET", None),
        ("Unicode Full-Width", "/unicode-bypassａ", None, "GET", None),
        
        # Container & Orchestration
        ("Docker Trust", "/docker-bypass", {"X-Docker-Content-Trust": "1"}, "GET", None),
        ("Docker Digest", "/docker-bypass", {"Docker-Content-Digest": "sha256:abc123"}, "GET", None),
        ("K8s Service", "/k8s-bypass", {"X-Kubernetes-Service": "admin-service"}, "GET", None),
        ("K8s Namespace", "/k8s-bypass", {"X-K8s-Namespace": "kube-system"}, "GET", None),
        ("Istio Metadata", "/istio-bypass", {"X-Envoy-Peer-Metadata": "admin_metadata"}, "GET", None),
        ("Istio Attributes", "/istio-bypass", {"X-Istio-Attributes": "admin_attrs"}, "GET", None),
    ]
    
    results = []
    successful_bypasses = 0
    total_tests = len(test_cases)
    
    print(f"Running {total_tests} specialized bypass tests...\n")
    
    for name, endpoint, headers, method, data in test_cases:
        print(f"Testing: {name:<30} ", end="")
        
        result = test_bypass(endpoint, headers, method, data)
        results.append((name, result))
        
        if result['success']:
            successful_bypasses += 1
            print(f"✓ SUCCESS ({result['status']})")
        else:
            status = result.get('status', 'ERR')
            print(f"✗ FAILED ({status})")
        
        time.sleep(0.05)  # Small delay between requests
    
    # Get lab statistics
    try:
        stats_response = requests.get(f"{LAB_URL}/stats", timeout=5)
        lab_stats = stats_response.json() if stats_response.status_code == 200 else {}
    except:
        lab_stats = {}
    
    # Print comprehensive summary
    print("\n" + "="*60)
    print("SPECIALIZED ENDPOINTS TEST SUMMARY")
    print("="*60)
    print(f"Total specialized tests: {total_tests}")
    print(f"Successful bypasses: {successful_bypasses}")
    print(f"Success rate: {successful_bypasses/total_tests*100:.1f}%")
    
    if lab_stats:
        print(f"Lab confirmed bypasses: {lab_stats.get('successful_bypasses', 0)}")
        print(f"Total lab requests: {lab_stats.get('total_attempts', 0)}")
        print(f"Lab success rate: {lab_stats.get('success_rate', 0):.1f}%")
    
    # Categorize results
    categories = {
        'Protocol & Method': ['Method Override', 'HTTP Version', 'Connect'],
        'Path Manipulation': ['Path Traversal', 'Path Dot', 'Encoded', 'Null Byte', 'Semicolon', 'Fragment'],
        'Header Pollution': ['XFF', 'Host', 'Smuggling'],
        'Load Balancer': ['AWS', 'F5', 'Nginx', 'Apache', 'HAProxy'],
        'Content & Accept': ['XML', 'Multipart', 'Accept', 'Charset'],
        'Authentication': ['Session', 'User ID', 'Cookie', 'Token'],
        'Rate Limiting': ['Rate Limit', 'Bot User'],
        'Geographic': ['Country', 'Client IP', 'Real IP'],
        'File & MIME': ['File Extension', 'MIME'],
        'Cache & CDN': ['Cache', 'Pragma', 'CDN'],
        'Modern Security': ['CSP', 'CSRF'],
        'Encoding': ['Double', 'Mixed', 'Unicode'],
        'Container': ['Docker', 'K8s', 'Istio'],
    }
    
    print(f"\nCategory Breakdown:")
    for category, keywords in categories.items():
        category_successes = sum(1 for name, result in results 
                               if result['success'] and any(kw in name for kw in keywords))
        category_total = sum(1 for name, result in results 
                           if any(kw in name for kw in keywords))
        if category_total > 0:
            print(f"  {category:<20}: {category_successes}/{category_total} ({category_successes/category_total*100:.0f}%)")
    
    # Show failed tests
    failed_tests = [(name, result) for name, result in results if not result['success']]
    if failed_tests:
        print(f"\nFailed tests ({len(failed_tests)}):")
        for name, result in failed_tests[:10]:  # Show first 10 failures
            status = result.get('status', 'unknown')
            error_msg = result.get('error', f"Status {status}")
            print(f"  - {name}: {error_msg}")
        if len(failed_tests) > 10:
            print(f"  ... and {len(failed_tests) - 10} more")
    
    return {
        'total_tests': total_tests,
        'successful_bypasses': successful_bypasses,
        'success_rate': successful_bypasses/total_tests*100,
        'lab_stats': lab_stats,
        'results': results
    }

if __name__ == "__main__":
    run_specialized_tests()