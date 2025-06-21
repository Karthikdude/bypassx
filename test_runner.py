#!/usr/bin/env python3
"""
BypassX Testing Suite - Automated validation of bypass techniques
"""

import subprocess
import time
import requests
import json
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple

class BypassXTester:
    def __init__(self, lab_url="http://127.0.0.1:5000", bypassx_binary="./bypassx"):
        self.lab_url = lab_url
        self.bypassx_binary = bypassx_binary
        self.test_results = []
        
    def wait_for_lab(self, timeout=30):
        """Wait for Flask lab to be ready"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = requests.get(f"{self.lab_url}/", timeout=5)
                if response.status_code == 200:
                    print(f"[INFO] Lab is ready at {self.lab_url}")
                    return True
            except requests.exceptions.RequestException:
                pass
            time.sleep(1)
        
        print(f"[ERROR] Lab not ready after {timeout} seconds")
        return False
    
    def run_bypassx_test(self, target_url: str, additional_args: List[str] = None) -> Dict:
        """Run bypassx against a target URL and capture results"""
        cmd = [self.bypassx_binary, "-u", target_url, "-verbose"]
        
        if additional_args:
            cmd.extend(additional_args)
        
        print(f"[TEST] Running: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return {
                'command': ' '.join(cmd),
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'target_url': target_url
            }
        except subprocess.TimeoutExpired:
            return {
                'command': ' '.join(cmd),
                'returncode': -1,
                'stdout': '',
                'stderr': 'Timeout expired',
                'target_url': target_url
            }
        except Exception as e:
            return {
                'command': ' '.join(cmd),
                'returncode': -1,
                'stdout': '',
                'stderr': str(e),
                'target_url': target_url
            }
    
    def parse_bypassx_output(self, output: str) -> List[Dict]:
        """Parse bypassx output to extract successful bypasses"""
        successes = []
        lines = output.split('\n')
        
        for line in lines:
            if '[BYPASS SUCCESS]' in line:
                # Parse: [BYPASS SUCCESS] URL: <url> | Method: <method> | Technique: <technique> | Status: <status>
                try:
                    parts = line.split(' | ')
                    url_part = parts[0].split('URL: ')[1] if 'URL: ' in parts[0] else ''
                    method_part = parts[1].split('Method: ')[1] if len(parts) > 1 and 'Method: ' in parts[1] else ''
                    technique_part = parts[2].split('Technique: ')[1] if len(parts) > 2 and 'Technique: ' in parts[2] else ''
                    status_part = int(parts[3].split('Status: ')[1]) if len(parts) > 3 and 'Status: ' in parts[3] else 0
                    
                    successes.append({
                        'url': url_part.strip(),
                        'method': method_part.strip(),
                        'technique': technique_part.strip(),
                        'status': status_part
                    })
                except (IndexError, ValueError) as e:
                    print(f"[WARNING] Failed to parse line: {line} - {e}")
        
        return successes
    
    def get_lab_stats(self) -> Dict:
        """Get statistics from the Flask lab"""
        try:
            response = requests.get(f"{self.lab_url}/stats", timeout=10)
            if response.status_code == 200:
                return response.json()
        except requests.exceptions.RequestException as e:
            print(f"[WARNING] Could not get lab stats: {e}")
        
        return {}
    
    def run_comprehensive_test(self) -> Dict:
        """Run comprehensive tests against all endpoints"""
        test_endpoints = [
            f"{self.lab_url}/admin",
            f"{self.lab_url}/api/admin", 
            f"{self.lab_url}/secure",
            f"{self.lab_url}/internal",
            f"{self.lab_url}/debug",
            f"{self.lab_url}/advanced"
        ]
        
        all_results = []
        total_bypasses = 0
        
        print(f"[INFO] Starting comprehensive test against {len(test_endpoints)} endpoints")
        
        # Test each endpoint
        for endpoint in test_endpoints:
            print(f"\n[INFO] Testing endpoint: {endpoint}")
            
            # Basic test
            result = self.run_bypassx_test(endpoint)
            all_results.append(result)
            
            # Parse results
            bypasses = self.parse_bypassx_output(result['stdout'])
            endpoint_bypasses = len(bypasses)
            total_bypasses += endpoint_bypasses
            
            print(f"[RESULT] {endpoint}: {endpoint_bypasses} bypasses found")
            
            # Show successful techniques
            for bypass in bypasses:
                print(f"  - {bypass['technique']} ({bypass['method']}) -> {bypass['status']}")
        
        # Get lab statistics
        lab_stats = self.get_lab_stats()
        
        return {
            'total_endpoints_tested': len(test_endpoints),
            'total_bypasses_found': total_bypasses,
            'bypassx_results': all_results,
            'lab_statistics': lab_stats,
            'test_summary': self.generate_test_summary(all_results, lab_stats)
        }
    
    def generate_test_summary(self, bypassx_results: List[Dict], lab_stats: Dict) -> Dict:
        """Generate comprehensive test summary"""
        total_requests = 0
        successful_bypasses = 0
        failed_requests = 0
        
        # Analyze bypassx results
        for result in bypassx_results:
            if result['returncode'] == 0:
                bypasses = self.parse_bypassx_output(result['stdout'])
                successful_bypasses += len(bypasses)
            else:
                failed_requests += 1
        
        # Get lab perspective
        lab_successful = lab_stats.get('successful_bypasses', 0)
        lab_total = lab_stats.get('total_attempts', 0)
        
        return {
            'bypassx_perspective': {
                'total_requests': sum(len(self.parse_bypassx_output(r['stdout']) + 
                                   [line for line in r['stdout'].split('\n') if '[FAILED]' in line]) 
                                   for r in bypassx_results),
                'successful_bypasses': successful_bypasses,
                'failed_requests': failed_requests
            },
            'lab_perspective': {
                'total_attempts': lab_total,
                'successful_bypasses': lab_successful,
                'success_rate': lab_stats.get('success_rate', 0)
            },
            'technique_breakdown': lab_stats.get('technique_breakdown', {}),
            'validation_status': 'PASSED' if successful_bypasses > 0 else 'FAILED'
        }
    
    def run_performance_test(self, target_url: str, concurrency_levels: List[int] = None) -> Dict:
        """Run performance tests with different concurrency levels"""
        if concurrency_levels is None:
            concurrency_levels = [1, 5, 10, 20]
        
        performance_results = []
        
        for concurrency in concurrency_levels:
            print(f"\n[PERF] Testing concurrency level: {concurrency}")
            
            start_time = time.time()
            result = self.run_bypassx_test(target_url, ["-t", str(concurrency)])
            end_time = time.time()
            
            duration = end_time - start_time
            bypasses = self.parse_bypassx_output(result['stdout'])
            
            performance_results.append({
                'concurrency': concurrency,
                'duration': duration,
                'bypasses_found': len(bypasses),
                'requests_per_second': len(bypasses) / duration if duration > 0 else 0,
                'success': result['returncode'] == 0
            })
            
            print(f"[PERF] Concurrency {concurrency}: {len(bypasses)} bypasses in {duration:.2f}s")
        
        return {
            'performance_results': performance_results,
            'best_performance': max(performance_results, key=lambda x: x['requests_per_second'])
        }
    
    def validate_technique_coverage(self) -> Dict:
        """Validate that all expected techniques are implemented"""
        expected_basic_techniques = [
            'HTTP_METHOD_OPTIONS', 'X_HTTP_METHOD_OVERRIDE_GET',
            'TRAILING_SLASH', 'TRAILING_DOT', 'CASE_MANIPULATION',
            'IP_SPOOF_X_FORWARDED_FOR', 'REFERER_MANIPULATION_0',
            'USER_AGENT_GOOGLEBOT', 'HOST_HEADER_localhost',
            'FORWARDED_Forwarded'
        ]
        
        expected_advanced_techniques = [
            'NULL_SEGMENT_0', 'UNICODE_VARIATION_0', 'DOUBLE_DECODE_0',
            'PATH_CONFUSION_0', 'VERB_TUNNELING_0', 'HEADER_POLLUTION_XFF'
        ]
        
        # Run against all endpoints to get full technique coverage
        all_endpoints = [
            f"{self.lab_url}/admin",
            f"{self.lab_url}/api/admin",
            f"{self.lab_url}/secure",
            f"{self.lab_url}/internal",
            f"{self.lab_url}/debug",
            f"{self.lab_url}/advanced"
        ]
        
        found_techniques = set()
        
        for endpoint in all_endpoints:
            result = self.run_bypassx_test(endpoint, ["-all"])
            bypasses = self.parse_bypassx_output(result['stdout'])
            for bypass in bypasses:
                found_techniques.add(bypass['technique'])
        
        # Check coverage
        basic_coverage = sum(1 for tech in expected_basic_techniques if tech in found_techniques)
        advanced_coverage = sum(1 for tech in expected_advanced_techniques if tech in found_techniques)
        
        return {
            'expected_basic': len(expected_basic_techniques),
            'found_basic': basic_coverage,
            'basic_coverage_percent': (basic_coverage / len(expected_basic_techniques)) * 100,
            'expected_advanced': len(expected_advanced_techniques),
            'found_advanced': advanced_coverage,
            'advanced_coverage_percent': (advanced_coverage / len(expected_advanced_techniques)) * 100,
            'total_techniques_found': len(found_techniques),
            'found_techniques': sorted(list(found_techniques)),
            'missing_basic': [tech for tech in expected_basic_techniques if tech not in found_techniques],
            'missing_advanced': [tech for tech in expected_advanced_techniques if tech not in found_techniques]
        }

def main():
    print("BypassX Testing Suite")
    print("=" * 50)
    
    # Check if bypassx binary exists
    bypassx_path = "./bypassx"
    if not os.path.exists(bypassx_path):
        print(f"[ERROR] BypassX binary not found at {bypassx_path}")
        print("Please compile the Go tool first: go build -o bypassx *.go")
        sys.exit(1)
    
    tester = BypassXTester()
    
    # Wait for lab to be ready
    if not tester.wait_for_lab():
        print("[ERROR] Flask lab is not running. Please start it first: python lab.py")
        sys.exit(1)
    
    # Run comprehensive test
    print("\n[INFO] Starting comprehensive functionality test...")
    comprehensive_results = tester.run_comprehensive_test()
    
    # Run performance test
    print("\n[INFO] Starting performance test...")
    performance_results = tester.run_performance_test(f"{tester.lab_url}/admin")
    
    # Validate technique coverage
    print("\n[INFO] Validating technique coverage...")
    coverage_results = tester.validate_technique_coverage()
    
    # Generate final report
    print("\n" + "=" * 60)
    print("FINAL TEST REPORT")
    print("=" * 60)
    
    # Summary
    summary = comprehensive_results['test_summary']
    print(f"Validation Status: {summary['validation_status']}")
    print(f"Total Bypasses Found: {summary['bypassx_perspective']['successful_bypasses']}")
    print(f"Lab Confirmed Bypasses: {summary['lab_perspective']['successful_bypasses']}")
    print(f"Lab Success Rate: {summary['lab_perspective']['success_rate']:.2f}%")
    
    # Performance
    best_perf = performance_results['best_performance']
    print(f"Best Performance: {best_perf['concurrency']} workers, {best_perf['requests_per_second']:.2f} req/sec")
    
    # Coverage
    print(f"Basic Technique Coverage: {coverage_results['basic_coverage_percent']:.1f}% ({coverage_results['found_basic']}/{coverage_results['expected_basic']})")
    print(f"Advanced Technique Coverage: {coverage_results['advanced_coverage_percent']:.1f}% ({coverage_results['found_advanced']}/{coverage_results['expected_advanced']})")
    print(f"Total Techniques Implemented: {coverage_results['total_techniques_found']}")
    
    # Missing techniques
    if coverage_results['missing_basic']:
        print(f"\nMissing Basic Techniques: {', '.join(coverage_results['missing_basic'])}")
    if coverage_results['missing_advanced']:
        print(f"Missing Advanced Techniques: {', '.join(coverage_results['missing_advanced'])}")
    
    # Write detailed results to file
    results_file = "test_results.json"
    with open(results_file, 'w') as f:
        json.dump({
            'comprehensive_results': comprehensive_results,
            'performance_results': performance_results,
            'coverage_results': coverage_results
        }, f, indent=2)
    
    print(f"\nDetailed results written to: {results_file}")
    
    # Determine overall success
    overall_success = (
        summary['validation_status'] == 'PASSED' and
        coverage_results['basic_coverage_percent'] >= 80 and
        coverage_results['advanced_coverage_percent'] >= 60 and
        best_perf['requests_per_second'] > 1
    )
    
    if overall_success:
        print("\n🎉 ALL TESTS PASSED! BypassX is working correctly!")
        sys.exit(0)
    else:
        print("\n❌ SOME TESTS FAILED. Check the results above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
