
package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// WorkItem represents a single bypass test to be performed
type WorkItem struct {
	URL       string
	Method    string
	Headers   map[string]string
	Body      string
	Technique string
}

func worker(workerID int, workChan <-chan WorkItem) {
	// Create HTTP client with custom configuration
	client := createHTTPClient()
	
	for workItem := range workChan {
		result := executeBypassTest(client, workItem)
		
		// Store result
		resultsMu.Lock()
		results = append(results, result)
		resultsMu.Unlock()
		
		// Print result if verbose
		if config.Verbose {
			if result.Success {
				fmt.Println(successColor(fmt.Sprintf("[WORKER %d] [SUCCESS] %s - %s (%d)",
					workerID, workItem.Technique, workItem.URL, result.Status)))
			} else {
				fmt.Println(failColor(fmt.Sprintf("[WORKER %d] [FAILED] %s - %s (%d)",
					workerID, workItem.Technique, workItem.URL, result.Status)))
			}
		}
	}
}

func createHTTPClient() *http.Client {
	// Create custom transport
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
	}
	
	// Configure proxy if specified
	if config.ProxyURL != "" {
		proxyURL, err := url.Parse(config.ProxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	
	return &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects, we want to see the initial response
			return http.ErrUseLastResponse
		},
	}
}

func executeBypassTest(client *http.Client, workItem WorkItem) Result {
	// Create request
	var bodyReader io.Reader
	if workItem.Body != "" {
		bodyReader = strings.NewReader(workItem.Body)
	}
	
	req, err := http.NewRequest(workItem.Method, workItem.URL, bodyReader)
	if err != nil {
		return Result{
			URL:       workItem.URL,
			Method:    workItem.Method,
			Technique: workItem.Technique,
			Status:    0,
			Success:   false,
		}
	}
	
	// Set headers
	setRequestHeaders(req, workItem.Headers)
	
	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return Result{
			URL:       workItem.URL,
			Method:    workItem.Method,
			Technique: workItem.Technique,
			Status:    0,
			Success:   false,
		}
	}
	defer resp.Body.Close()
	
	// Check if status code indicates success
	success := isSuccessStatusCode(resp.StatusCode)
	
	return Result{
		URL:       workItem.URL,
		Method:    workItem.Method,
		Technique: workItem.Technique,
		Status:    resp.StatusCode,
		Success:   success,
	}
}

func setRequestHeaders(req *http.Request, headers map[string]string) {
	// Set custom headers from config
	for key, value := range config.CustomHeaders {
		req.Header.Set(key, value)
	}
	
	// Set technique-specific headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	
	// Set cookie if specified
	if config.Cookie != "" {
		req.Header.Set("Cookie", config.Cookie)
	}
	
	// Set User-Agent if not already set
	if req.Header.Get("User-Agent") == "" && len(config.UserAgents) > 0 {
		req.Header.Set("User-Agent", config.UserAgents[0])
	}
	
	// Set Content-Type for POST requests if not specified
	if req.Method == "POST" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
}

func isSuccessStatusCode(statusCode int) bool {
	for _, code := range config.SuccessCodes {
		if statusCode == code {
			return true
		}
	}
	return false
}

// Additional helper functions for advanced request manipulation
func createRequestWithBody(method, url, body string) (*http.Request, error) {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = bytes.NewBufferString(body)
	}
	return http.NewRequest(method, url, bodyReader)
}

func setAdvancedHeaders(req *http.Request, technique string) {
	switch technique {
	case "REQUEST_SMUGGLING_TE_CL":
		req.Header.Set("Transfer-Encoding", "chunked")
		req.Header.Set("Content-Length", "0")
	case "HTTP2_AUTHORITY_BYPASS":
		// Note: This won't work with http/1.1 but is included for completeness
		req.Header.Set(":authority", "internal.service")
	case "WEBSOCKET_UPGRADE":
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Sec-WebSocket-Key", "x3JJHMbDL1EzLkh9GBhXDw==")
		req.Header.Set("Sec-WebSocket-Version", "13")
	}
}

func handleSpecialRequests(client *http.Client, workItem WorkItem) *Result {
	// Handle special cases that need custom request handling
	switch workItem.Technique {
	case "CRLF_INJECTION":
		return handleCRLFInjection(client, workItem)
	case "NULL_BYTE_INJECTION":
		return handleNullByteInjection(client, workItem)
	}
	return nil
}

func handleCRLFInjection(client *http.Client, workItem WorkItem) *Result {
	// For CRLF injection, we need to construct a raw request
	// This is a simplified version - real CRLF injection would need raw socket handling
	modifiedURL := workItem.URL + "%0d%0aInjected: header"
	
	req, err := http.NewRequest(workItem.Method, modifiedURL, nil)
	if err != nil {
		return &Result{
			URL:       workItem.URL,
			Method:    workItem.Method,
			Technique: workItem.Technique,
			Status:    0,
			Success:   false,
		}
	}
	
	setRequestHeaders(req, workItem.Headers)
	
	resp, err := client.Do(req)
	if err != nil {
		return &Result{
			URL:       workItem.URL,
			Method:    workItem.Method,
			Technique: workItem.Technique,
			Status:    0,
			Success:   false,
		}
	}
	defer resp.Body.Close()
	
	return &Result{
		URL:       workItem.URL,
		Method:    workItem.Method,
		Technique: workItem.Technique,
		Status:    resp.StatusCode,
		Success:   isSuccessStatusCode(resp.StatusCode),
	}
}

func handleNullByteInjection(client *http.Client, workItem WorkItem) *Result {
	// Handle null byte injection
	req, err := http.NewRequest(workItem.Method, workItem.URL, nil)
	if err != nil {
		return &Result{
			URL:       workItem.URL,
			Method:    workItem.Method,
			Technique: workItem.Technique,
			Status:    0,
			Success:   false,
		}
	}
	
	setRequestHeaders(req, workItem.Headers)
	
	resp, err := client.Do(req)
	if err != nil {
		return &Result{
			URL:       workItem.URL,
			Method:    workItem.Method,
			Technique: workItem.Technique,
			Status:    0,
			Success:   false,
		}
	}
	defer resp.Body.Close()
	
	return &Result{
		URL:       workItem.URL,
		Method:    workItem.Method,
		Technique: workItem.Technique,
		Status:    resp.StatusCode,
		Success:   isSuccessStatusCode(resp.StatusCode),
	}
}
