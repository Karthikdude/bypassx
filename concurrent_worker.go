package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// WorkItem represents a single bypass attempt
type WorkItem struct {
	URL       string
	Method    string
	Headers   map[string]string
	Body      string
	Technique string
}

func worker(workerID int, workChan <-chan WorkItem) {
	// Create HTTP client for this worker
	client := createHTTPClient()
	
	for workItem := range workChan {
		result := processWorkItem(client, workItem)
		
		// Store result safely
		resultsMu.Lock()
		results = append(results, result)
		resultsMu.Unlock()
		
		// Output result if verbose or successful
		if result.Success || config.Verbose {
			if result.Success {
				fmt.Printf("[WORKER %d] [SUCCESS] %s | %s | %s | %d\n",
					workerID, workItem.Technique, workItem.Method, workItem.URL, result.Status)
			} else if config.Verbose {
				fmt.Printf("[WORKER %d] [FAILED] %s | %s | %s | %d\n",
					workerID, workItem.Technique, workItem.Method, workItem.URL, result.Status)
			}
		}
	}
}

func createHTTPClient() *http.Client {
	// Configure transport
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // For testing purposes
		},
		DisableKeepAlives: true,
		MaxIdleConns:      1,
		IdleConnTimeout:   time.Second * 5,
	}
	
	// Configure proxy if specified
	if config.ProxyURL != "" {
		proxyURL, err := url.Parse(config.ProxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	
	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects, we want to capture them
			return http.ErrUseLastResponse
		},
	}
	
	return client
}

func processWorkItem(client *http.Client, workItem WorkItem) Result {
	result := Result{
		URL:       workItem.URL,
		Method:    workItem.Method,
		Technique: workItem.Technique,
		Success:   false,
	}
	
	// Create request
	var bodyReader io.Reader
	if workItem.Body != "" {
		bodyReader = strings.NewReader(workItem.Body)
	}
	
	req, err := http.NewRequest(workItem.Method, workItem.URL, bodyReader)
	if err != nil {
		result.Status = 0
		return result
	}
	
	// Set headers
	setRequestHeaders(req, workItem.Headers)
	
	// Make request
	resp, err := client.Do(req)
	if err != nil {
		result.Status = 0
		return result
	}
	defer resp.Body.Close()
	
	result.Status = resp.StatusCode
	
	// Check if this is a success based on configured success codes
	for _, successCode := range config.SuccessCodes {
		if resp.StatusCode == successCode {
			result.Success = true
			break
		}
	}
	
	return result
}

func setRequestHeaders(req *http.Request, techniqueHeaders map[string]string) {
	// Set default headers
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", config.UserAgents[0])
	}
	
	// Set custom headers from config
	for key, value := range config.CustomHeaders {
		req.Header.Set(key, value)
	}
	
	// Set technique-specific headers
	for key, value := range techniqueHeaders {
		// Handle special cases for certain headers
		switch key {
		case "Host":
			req.Host = value
		case "X-Forwarded-For":
			// Handle multiple values
			if existing := req.Header.Get(key); existing != "" {
				req.Header.Set(key, existing+", "+value)
			} else {
				req.Header.Set(key, value)
			}
		default:
			req.Header.Set(key, value)
		}
	}
	
	// Set cookie if provided
	if config.Cookie != "" {
		req.Header.Set("Cookie", config.Cookie)
	}
	
	// Set content length for POST requests with body
	if req.Body != nil && req.Method == "POST" {
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
}
