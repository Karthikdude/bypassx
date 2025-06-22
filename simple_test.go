package main

import (
	"fmt"
	"net/http"
	"time"
)

func main() {
	// Test basic functionality
	client := &http.Client{Timeout: 5 * time.Second}
	
	// Test cases with expected bypasses
	testCases := []struct {
		name     string
		url      string
		headers  map[string]string
		expected bool
	}{
		{"Trailing slash", "http://127.0.0.1:5000/admin/", nil, true},
		{"X-Forwarded-For", "http://127.0.0.1:5000/admin", map[string]string{"X-Forwarded-For": "127.0.0.1"}, true},
		{"Cloudflare IP", "http://127.0.0.1:5000/waf", map[string]string{"CF-Connecting-IP": "127.0.0.1"}, true},
		{"Default admin", "http://127.0.0.1:5000/admin", nil, false},
	}
	
	fmt.Println("Simple BypassX Test")
	fmt.Println("==================")
	
	successful := 0
	
	for _, tc := range testCases {
		req, _ := http.NewRequest("GET", tc.url, nil)
		
		for k, v := range tc.headers {
			req.Header.Set(k, v)
		}
		
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("%-20s ERROR: %v\n", tc.name, err)
			continue
		}
		resp.Body.Close()
		
		success := resp.StatusCode == 200
		if success == tc.expected {
			if success {
				fmt.Printf("%-20s ✓ BYPASS SUCCESS (%d)\n", tc.name, resp.StatusCode)
				successful++
			} else {
				fmt.Printf("%-20s ✓ BLOCKED AS EXPECTED (%d)\n", tc.name, resp.StatusCode)
				successful++
			}
		} else {
			fmt.Printf("%-20s ✗ UNEXPECTED (%d)\n", tc.name, resp.StatusCode)
		}
	}
	
	fmt.Printf("\nResult: %d/%d tests passed\n", successful, len(testCases))
	if successful == len(testCases) {
		fmt.Println("🎉 All tests passed! BypassX functionality confirmed!")
	}
}