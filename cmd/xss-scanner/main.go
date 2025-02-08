package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/1takaonaiinc/xss-scanner/pkg/banner"
	"github.com/1takaonaiinc/xss-scanner/pkg/crawler"
	"github.com/1takaonaiinc/xss-scanner/pkg/scanner"
	"github.com/manifoldco/promptui"
)

func main() {
	// Display banner
	banner.Print()
	defer banner.Cleanup()

	// Interactive URL input
	urlPrompt := promptui.Prompt{
		Label:    "Target URL",
		Validate: validateURL,
	}
	targetURL, err := urlPrompt.Run()
	if err != nil {
		fmt.Printf("URL input error: %v\n", err)
		os.Exit(1)
	}

	// Interactive patterns input
	patternsPrompt := promptui.Prompt{
		Label:   "Custom XSS patterns (comma-separated, press enter for defaults)",
		Default: "",
	}
	customPatterns, _ := patternsPrompt.Run()

	// Model file selection
	modelPrompt := promptui.Prompt{
		Label:   "ML model file path (press enter for default)",
		Default: "models/default.json",
	}
	mlModel, _ := modelPrompt.Run()

	// ML threshold
	thresholdPrompt := promptui.Prompt{
		Label:    "ML detection threshold (0.0-1.0)",
		Default:  "0.7",
		Validate: validateThreshold,
	}
	thresholdStr, _ := thresholdPrompt.Run()
	mlThreshold, _ := strconv.ParseFloat(thresholdStr, 64)

	// Excluded URLs
	excludePrompt := promptui.Prompt{
		Label:   "URLs to exclude (comma-separated)",
		Default: "",
	}
	excludeUrls, _ := excludePrompt.Run()

	// Parameters to check
	paramsPrompt := promptui.Prompt{
		Label:   "Parameters to specifically check (comma-separated)",
		Default: "",
	}
	includeParams, _ := paramsPrompt.Run()

	// Timeout
	timeoutPrompt := promptui.Prompt{
		Label:    "Timeout in seconds",
		Default:  "30",
		Validate: validateNumber,
	}
	timeoutStr, _ := timeoutPrompt.Run()
	timeout, _ := strconv.Atoi(timeoutStr)

	// Concurrent scans
	concurrentPrompt := promptui.Prompt{
		Label:    "Number of concurrent scans",
		Default:  "5",
		Validate: validateNumber,
	}
	concurrentStr, _ := concurrentPrompt.Run()
	concurrent, _ := strconv.Atoi(concurrentStr)

	// Custom headers
	headersPrompt := promptui.Prompt{
		Label:   "Custom headers (format: key1:value1,key2:value2)",
		Default: "",
	}
	headers, _ := headersPrompt.Run()

	// Crawling depth
	depthPrompt := promptui.Prompt{
		Label:    "Crawling depth",
		Default:  "2",
		Validate: validateNumber,
	}
	depthStr, _ := depthPrompt.Run()
	depth, _ := strconv.Atoi(depthStr)

	// Verbose mode
	verboseSelect := promptui.Select{
		Label: "Enable verbose output",
		Items: []string{"Yes", "No"},
	}
	_, verboseStr, _ := verboseSelect.Run()
	verbose := verboseStr == "Yes"

	// Parse headers
	headerMap := make(map[string]string)
	if headers != "" {
		headerPairs := strings.Split(headers, ",")
		for _, pair := range headerPairs {
			parts := strings.SplitN(pair, ":", 2)
			if len(parts) == 2 {
				headerMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	// Initialize crawler with depth
	c := crawler.NewCrawler()
	c.SetMaxDepth(depth)

	if verbose {
		fmt.Printf("Crawling %s with depth %d...\n", targetURL, depth)
	}

	pages, keywords, err := c.Crawl(targetURL)
	if err != nil {
		fmt.Printf("Crawling error: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Println("Extracted Keywords:", keywords)
	}

	// Initialize scanner with options
	scanOpts := scanner.Options{
		Patterns:       strings.Split(customPatterns, ","),
		Verbose:        verbose,
		MLModel:        mlModel,
		MLThreshold:    mlThreshold,
		ExcludeUrls:    strings.Split(excludeUrls, ","),
		IncludeParams:  strings.Split(includeParams, ","),
		TimeoutSeconds: timeout,
		MaxConcurrency: concurrent,
		Headers:        headerMap,
	}

	s, err := scanner.NewScanner(scanOpts)
	if err != nil {
		fmt.Printf("Scanner initialization error: %v\n", err)
		os.Exit(1)
	}

	// Start scanning
	startTime := time.Now()
	if verbose {
		fmt.Printf("\nScanning %d pages...\n", len(pages))
	}

	results := s.ScanPages(pages)

	if verbose {
		fmt.Printf("\nScan completed in %s\n", time.Since(startTime))
	}

	// Output results
	fmt.Printf("\nXSS Vulnerability Report for %s:\n", targetURL)
	fmt.Printf("Scanned %d pages\n", len(pages))

	var high, medium int
	for _, result := range results {
		fmt.Printf("[%s] %s\n\t%s\n", result.Severity, result.Description, result.Payload)
		if result.Severity == "High" {
			high++
		} else if result.Severity == "Medium" {
			medium++
		}
	}

	fmt.Printf("\nSummary:\n")
	fmt.Printf("- High severity issues: %d\n", high)
	fmt.Printf("- Medium severity issues: %d\n", medium)
	fmt.Printf("- Total scan time: %s\n", time.Since(startTime))
}

func validateURL(input string) error {
	if input == "" {
		return fmt.Errorf("URL cannot be empty")
	}
	if !strings.HasPrefix(input, "http://") && !strings.HasPrefix(input, "https://") {
		return fmt.Errorf("URL must start with http:// or https://")
	}
	return nil
}

func validateThreshold(input string) error {
	threshold, err := strconv.ParseFloat(input, 64)
	if err != nil {
		return fmt.Errorf("must be a valid number")
	}
	if threshold < 0 || threshold > 1 {
		return fmt.Errorf("must be between 0.0 and 1.0")
	}
	return nil
}

func validateNumber(input string) error {
	num, err := strconv.Atoi(input)
	if err != nil {
		return fmt.Errorf("must be a valid number")
	}
	if num < 1 {
		return fmt.Errorf("must be greater than 0")
	}
	return nil
}
