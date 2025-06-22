package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// Config holds all configuration options
type Config struct {
        TargetURL        string
        URLListFile      string
        HeaderFile       string
        Method           string
        OutputFile       string
        Concurrency      int
        Timeout          time.Duration
        Verbose          bool
        ProxyURL         string
        Cookie           string
        Data             string
        UseStdin         bool
        All              bool
        Basic            bool
        Advanced         bool
        ProtocolMethod   bool
        PathManipulation bool
        HeaderPollution  bool
        LoadBalancer     bool
        ContentType      bool
        Authentication   bool
        RateLimit        bool
        Geographic       bool
        FileExtension    bool
        Cache            bool
        ModernSecurity   bool
        Encoding         bool
        Container        bool
        Ports            string
        StatusCodes      string
        WordlistFile     string
        UserAgentFile    string
        Details          string
        SuccessCodes     []int
        CustomHeaders    map[string]string
        UserAgents       []string
}

// Result represents a bypass attempt result
type Result struct {
        URL       string
        Method    string
        Technique string
        Status    int
        Success   bool
}

var (
	results   []Result
	resultsMu sync.Mutex
	config    Config

	// Color functions
	infoColor    = color.New(color.FgCyan).SprintFunc()
	successColor = color.New(color.FgGreen).SprintFunc()
	failColor    = color.New(color.FgRed).SprintFunc()
	boldColor    = color.New(color.Bold).SprintFunc()
)

func showDetails(technique string) {
	// If no technique specified, show available techniques
	if technique == "" {
		fmt.Println("\nAvailable techniques (use -details TECHNIQUE_NAME):")
		fmt.Println(strings.Repeat("-", 50))
		
		// List all available techniques from the details directory
		files, err := os.ReadDir("details")
		if err != nil {
			fmt.Printf("Error reading details directory: %v\n", err)
			os.Exit(1)
		}
		
		// Group techniques by category for better readability
		categories := make(map[string][]string)
		for _, file := range files {
			if strings.HasSuffix(file.Name(), ".md") {
				techName := strings.TrimSuffix(file.Name(), ".md")
				// Simple categorization based on technique name
				category := "Other"
				switch {
				case strings.HasPrefix(techName, "TRAILING_"):
					category = "Trailing Character Manipulation"
				case strings.Contains(techName, "HEADER_"):
					category = "Header Manipulation"
				case strings.Contains(techName, "CASE_"):
					category = "Case Manipulation"
				case strings.Contains(techName, "ENCODED") || strings.Contains(techName, "ENCODING"):
					category = "Encoding Manipulation"
				case strings.Contains(techName, "BYPASS"):
					category = "Specific Bypass Techniques"
				}
				categories[category] = append(categories[category], techName)
			}
		}
		
		// Print techniques by category
		for category, techs := range categories {
			fmt.Printf("\n[%s]\n", category)
			for _, tech := range techs {
				fmt.Printf("  %s\n", tech)
			}
		}
		fmt.Println("\nExample: bypassx -details TRAILING_SLASH")
		os.Exit(0)
	}

	// Normalize technique name (case-insensitive, remove .md if present)
	technique = strings.ToUpper(strings.TrimSuffix(technique, ".md"))
	detailsPath := filepath.Join("details", technique+".md")
	
	// Check if file exists
	if _, err := os.Stat(detailsPath); os.IsNotExist(err) {
		fmt.Printf("\nError: Documentation not found for technique: %s\n", technique)
		fmt.Println("\nRun 'bypassx -details' to see available techniques")
		os.Exit(1)
	}

	// Read and display the file
	content, err := os.ReadFile(detailsPath)
	if err != nil {
		fmt.Printf("Error reading documentation: %v\n", err)
		os.Exit(1)
	}

	// Display with some formatting
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Printf(" %s Documentation\n", technique)
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println(string(content))
	fmt.Println(strings.Repeat("=", 80))
}

func main() {
        parseFlags()
        loadCustomHeaders()
        loadUserAgents()
        parseSuccessCodes()

        // Handle details flag
        if config.Details != "" {
                showDetails(config.Details)
                return
        }

        if config.TargetURL == "" && config.URLListFile == "" && !config.UseStdin {
                fmt.Println("Error: Please provide a target URL (-u), URL list file (-l), or use stdin (-stdin)")
                os.Exit(1)
        }

        if config.TargetURL != "" && config.URLListFile != "" {
                fmt.Println("Error: Please provide either a target URL (-u) or URL list file (-l), not both")
                os.Exit(1)
        }

        if config.TargetURL != "" && config.UseStdin {
                fmt.Println("Error: Please provide either a target URL (-u) or use stdin (-stdin), not both")
                os.Exit(1)
        }

        if config.URLListFile != "" && config.UseStdin {
                fmt.Println("Error: Please provide either a URL list file (-l) or use stdin (-stdin), not both")
                os.Exit(1)
        }

        if config.OutputFile != "" {
                outputFile, err := os.Create(config.OutputFile)
                if err != nil {
                        log.Fatal(err)
                }
                defer outputFile.Close()
                log.SetOutput(outputFile)
        }

        // Get target URLs
        urls := getTargetURLs()
        if len(urls) == 0 {
                log.Fatal("No target URLs provided")
        }

        fmt.Println(infoColor(fmt.Sprintf("[INFO] Starting bypassx with %d URLs and %d workers", len(urls), config.Concurrency)))
		fmt.Println(infoColor(fmt.Sprintf("[INFO] Success codes: %v", config.SuccessCodes)))
        
        // Start concurrent processing
        startTime := time.Now()
        processURLs(urls)
        duration := time.Since(startTime)

        // Print summary
        printSummary(duration)
        
        // Write results to file if specified
        if config.OutputFile != "" {
                writeResultsToFile()
        }
}

func parseFlags() {
        flag.StringVar(&config.TargetURL, "u", "", "Target URL to test")
        flag.StringVar(&config.URLListFile, "l", "", "File containing list of target URLs")
        flag.StringVar(&config.HeaderFile, "H", "", "File containing custom headers")
        flag.StringVar(&config.Method, "m", "", "HTTP method to use (default: all)")
        flag.StringVar(&config.OutputFile, "o", "", "Output file for results")
        flag.StringVar(&config.Details, "details", "", "Show detailed documentation for a specific bypass technique")
        flag.IntVar(&config.Concurrency, "t", 10, "Number of concurrent workers")
        timeoutSeconds := flag.Int("timeout", 10, "Request timeout in seconds")
        flag.BoolVar(&config.Verbose, "verbose", false, "Enable verbose output")
        flag.StringVar(&config.ProxyURL, "proxy", "", "Proxy URL")
        flag.StringVar(&config.Cookie, "cookie", "", "Cookie string")
        flag.StringVar(&config.Data, "data", "", "POST data")
        flag.BoolVar(&config.UseStdin, "stdin", false, "Read URLs from stdin")
        flag.BoolVar(&config.All, "all", true, "Enable all bypass techniques")
        flag.BoolVar(&config.Basic, "basic", false, "Enable only basic techniques")
        flag.BoolVar(&config.Advanced, "advanced", false, "Enable only advanced techniques")
        flag.BoolVar(&config.ProtocolMethod, "protocol", false, "Enable protocol and method bypasses")
        flag.BoolVar(&config.PathManipulation, "path", false, "Enable advanced path manipulation")
        flag.BoolVar(&config.HeaderPollution, "headers", false, "Enable header pollution techniques")
        flag.BoolVar(&config.LoadBalancer, "lb", false, "Enable load balancer bypasses")
        flag.BoolVar(&config.ContentType, "content", false, "Enable content-type bypasses")
        flag.BoolVar(&config.Authentication, "auth", false, "Enable authentication bypasses")
        flag.BoolVar(&config.RateLimit, "rate", false, "Enable rate limiting bypasses")
        flag.BoolVar(&config.Geographic, "geo", false, "Enable geographic bypasses")
        flag.BoolVar(&config.FileExtension, "file", false, "Enable file extension bypasses")
        flag.BoolVar(&config.Cache, "cache", false, "Enable cache bypasses")
        flag.BoolVar(&config.ModernSecurity, "modern", false, "Enable modern security bypasses")
        flag.BoolVar(&config.Encoding, "encode", false, "Enable encoding bypasses")
        flag.BoolVar(&config.Container, "container", false, "Enable container bypasses")
        flag.StringVar(&config.Ports, "port", "", "Additional ports to test (comma-separated)")
        flag.StringVar(&config.StatusCodes, "status", "200,302,401", "Success status codes (comma-separated)")
        flag.StringVar(&config.WordlistFile, "wordlist", "", "Path wordlist file")
        flag.StringVar(&config.UserAgentFile, "user-agent-file", "", "User agent file")
        
        flag.Parse()
        
        config.Timeout = time.Duration(*timeoutSeconds) * time.Second
        
        // Adjust technique flags
        if config.Basic || config.Advanced || config.ProtocolMethod || config.PathManipulation || 
           config.HeaderPollution || config.LoadBalancer || config.ContentType || config.Authentication ||
           config.RateLimit || config.Geographic || config.FileExtension || config.Cache ||
           config.ModernSecurity || config.Encoding || config.Container {
                config.All = false
        }
}

func loadCustomHeaders() {
        config.CustomHeaders = make(map[string]string)
        
        if config.HeaderFile == "" {
                return
        }
        
        file, err := os.Open(config.HeaderFile)
        if err != nil {
                log.Printf("[WARNING] Could not open header file: %v", err)
                return
        }
        defer file.Close()
        
        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
                line := strings.TrimSpace(scanner.Text())
                if line == "" || strings.HasPrefix(line, "#") {
                        continue
                }
                
                parts := strings.SplitN(line, ":", 2)
                if len(parts) == 2 {
                        key := strings.TrimSpace(parts[0])
                        value := strings.TrimSpace(parts[1])
                        config.CustomHeaders[key] = value
                }
        }
        
        fmt.Printf("[INFO] Loaded %d custom headers\n", len(config.CustomHeaders))
}

func loadUserAgents() {
        // Default user agents
        config.UserAgents = []string{
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
                "Googlebot/2.1 (+http://www.google.com/bot.html)",
        }
        
        if config.UserAgentFile == "" {
                return
        }
        
        file, err := os.Open(config.UserAgentFile)
        if err != nil {
                log.Printf("[WARNING] Could not open user agent file: %v", err)
                return
        }
        defer file.Close()
        
        var userAgents []string
        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
                line := strings.TrimSpace(scanner.Text())
                if line != "" && !strings.HasPrefix(line, "#") {
                        userAgents = append(userAgents, line)
                }
        }
        
        if len(userAgents) > 0 {
                config.UserAgents = userAgents
                fmt.Printf("[INFO] Loaded %d custom user agents\n", len(userAgents))
        }
}

func parseSuccessCodes() {
        codes := strings.Split(config.StatusCodes, ",")
        for _, code := range codes {
                if num, err := strconv.Atoi(strings.TrimSpace(code)); err == nil {
                        config.SuccessCodes = append(config.SuccessCodes, num)
                }
        }
        
        if len(config.SuccessCodes) == 0 {
                config.SuccessCodes = []int{200, 302, 401}
        }
}

func getTargetURLs() []string {
        var urls []string
        
        if config.TargetURL != "" {
                urls = append(urls, config.TargetURL)
        }
        
        if config.URLListFile != "" {
                fileURLs := readURLsFromFile(config.URLListFile)
                urls = append(urls, fileURLs...)
        }
        
        if config.UseStdin {
                stdinURLs := readURLsFromStdin()
                urls = append(urls, stdinURLs...)
        }
        
        return urls
}

func readURLsFromFile(filename string) []string {
        file, err := os.Open(filename)
        if err != nil {
                log.Printf("[ERROR] Could not open URL file: %v", err)
                return nil
        }
        defer file.Close()
        
        var urls []string
        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
                line := strings.TrimSpace(scanner.Text())
                if line != "" && !strings.HasPrefix(line, "#") {
                        urls = append(urls, line)
                }
        }
        
        return urls
}

func readURLsFromStdin() []string {
        var urls []string
        scanner := bufio.NewScanner(os.Stdin)
        for scanner.Scan() {
                line := strings.TrimSpace(scanner.Text())
                if line != "" && !strings.HasPrefix(line, "#") {
                        urls = append(urls, line)
                }
        }
        
        return urls
}

func processURLs(urls []string) {
        // Create work channel
        workChan := make(chan WorkItem, config.Concurrency*2)
        
        // Start workers
        var wg sync.WaitGroup
        for i := 0; i < config.Concurrency; i++ {
                wg.Add(1)
                go func(workerID int) {
                        defer wg.Done()
                        worker(workerID, workChan)
                }(i)
        }
        
        // Send work items
        go func() {
                defer close(workChan)
                
                for _, url := range urls {
                        // Generate all bypass techniques for this URL
                        techniques := generateBypassTechniques(url)
                        
                        for _, technique := range techniques {
                                workChan <- WorkItem{
                                        URL:       technique.URL,
                                        Method:    technique.Method,
                                        Headers:   technique.Headers,
                                        Body:      technique.Body,
                                        Technique: technique.Name,
                                }
                        }
                }
        }()
        
        // Wait for all workers to complete
        wg.Wait()
}

func printSummary(duration time.Duration) {
	successCount := 0
	totalCount := len(results)

	fmt.Printf("\n" + strings.Repeat("=", 60) + "\n")
	fmt.Println(boldColor("BYPASSX SCAN SUMMARY"))
	fmt.Printf(strings.Repeat("=", 60) + "\n")

	// Print all results
	for _, result := range results {
		if result.Success {
			fmt.Println(successColor(fmt.Sprintf("[BYPASS SUCCESS] URL: %s | Method: %s | Technique: %s | Status: %d",
				result.URL, result.Method, result.Technique, result.Status)))
			successCount++
		} else if config.Verbose {
			fmt.Println(failColor(fmt.Sprintf("[FAILED] URL: %s | Method: %s | Technique: %s | Status: %d",
				result.URL, result.Method, result.Technique, result.Status)))
		}
	}

	fmt.Printf(strings.Repeat("-", 60) + "\n")
	fmt.Printf("Total requests: %d\n", totalCount)
	fmt.Printf("Successful bypasses: %s\n", successColor(successCount))
	fmt.Printf("Success rate: %.2f%%\n", float64(successCount)/float64(totalCount)*100)
	fmt.Printf("Scan duration: %v\n", duration)
	fmt.Printf(strings.Repeat("=", 60) + "\n")
}

func writeResultsToFile() {
	file, err := os.Create(config.OutputFile)
	if err != nil {
		log.Printf("[ERROR] Could not create output file: %v", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	for _, result := range results {
		if result.Success {
			line := fmt.Sprintf("[BYPASS SUCCESS] URL: %s | Method: %s | Technique: %s | Status: %d\n",
				result.URL, result.Method, result.Technique, result.Status)
			writer.WriteString(line)
		}
	}

	fmt.Println(infoColor(fmt.Sprintf("[INFO] Results written to %s", config.OutputFile)))
}
