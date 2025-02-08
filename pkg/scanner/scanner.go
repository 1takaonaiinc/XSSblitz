package scanner

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/1takaonaiinc/xss-scanner/pkg/predictor"
)

type Options struct {
	Patterns       []string
	Verbose        bool
	MLModel        string
	MLThreshold    float64
	ExcludeUrls    []string
	IncludeParams  []string
	TimeoutSeconds int
	MaxConcurrency int
	Headers        map[string]string
}

type ScannerConfig struct {
	CustomHeaders   map[string]string
	TimeoutSeconds  int
	MaxConcurrency  int
	ExcludePatterns []string
	IncludeParams   []string
}

type Scanner struct {
	patterns  []string
	verbose   bool
	predictor *predictor.Predictor
	config    ScannerConfig
}

type ScanResult struct {
	Severity    string
	Description string
	Payload     string
}

var defaultPatterns = []string{
	"<script>",
	"javascript:",
	"onerror=",
	"onload=",
	"onclick=",
	"onmouseover=",
	"eval(",
	"alert(",
	"document.cookie",
	"localStorage",
}

func NewScanner(opts Options) (*Scanner, error) {
	patterns := defaultPatterns
	if len(opts.Patterns) > 0 {
		patterns = opts.Patterns
	}

	pred, err := predictor.NewPredictor(opts.MLModel)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize predictor: %v", err)
	}

	config := ScannerConfig{
		CustomHeaders:   opts.Headers,
		TimeoutSeconds:  opts.TimeoutSeconds,
		MaxConcurrency:  opts.MaxConcurrency,
		ExcludePatterns: opts.ExcludeUrls,
		IncludeParams:   opts.IncludeParams,
	}

	return &Scanner{
		patterns:  patterns,
		verbose:   opts.Verbose,
		predictor: pred,
		config:    config,
	}, nil
}

func (s *Scanner) ScanPages(pages []string) []ScanResult {
	results := make([]ScanResult, 0)
	semaphore := make(chan bool, s.config.MaxConcurrency)
	resultChan := make(chan ScanResult)
	done := make(chan bool)

	// Start worker goroutine to collect results
	go func() {
		for result := range resultChan {
			results = append(results, result)
		}
		done <- true
	}()

	// Process pages concurrently
	for _, page := range pages {
		semaphore <- true
		go func(url string) {
			defer func() { <-semaphore }()
			s.scanPage(url, resultChan)
		}(page)
	}

	// Wait for all workers to finish
	for i := 0; i < cap(semaphore); i++ {
		semaphore <- true
	}
	close(resultChan)
	<-done

	return results
}

func (s *Scanner) scanPage(page string, resultChan chan<- ScanResult) {
	// Check if URL should be excluded
	for _, pattern := range s.config.ExcludePatterns {
		if strings.Contains(page, pattern) {
			if s.verbose {
				fmt.Printf("Skipping excluded URL: %s\n", page)
			}
			return
		}
	}

	client := &http.Client{
		Timeout: time.Duration(s.config.TimeoutSeconds) * time.Second,
	}

	req, err := http.NewRequest("GET", page, nil)
	if err != nil {
		if s.verbose {
			fmt.Printf("Failed to create request for %s: %v\n", page, err)
		}
		return
	}

	// Add custom headers
	for key, value := range s.config.CustomHeaders {
		req.Header.Add(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		if s.verbose {
			fmt.Printf("Failed to fetch page %s: %v\n", page, err)
		}
		return
	}
	defer resp.Body.Close()

	if !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		if s.verbose {
			fmt.Printf("Skipping non-HTML content: %s\n", page)
		}
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if s.verbose {
			fmt.Printf("Failed to read body of %s: %v\n", page, err)
		}
		return
	}

	content := string(body)

	// Use ML predictor
	isXSS, score, contributions := s.predictor.IsXSS(content)
	if isXSS {
		resultChan <- ScanResult{
			Severity:    "High",
			Description: fmt.Sprintf("ML-detected XSS vulnerability on %s (confidence: %.2f%%)", page, score*100),
			Payload:     fmt.Sprintf("Contributing factors: %v", contributions),
		}
	}

	// Traditional pattern matching
	for _, pattern := range s.patterns {
		if strings.Contains(content, pattern) {
			resultChan <- ScanResult{
				Severity:    "High",
				Description: fmt.Sprintf("Pattern-matched XSS vulnerability on %s", page),
				Payload:     fmt.Sprintf("Found pattern: %s", pattern),
			}
		}
	}

	// Check for reflected parameters
	params := resp.Request.URL.Query()
	for key, values := range params {
		// Skip if not in included parameters
		if len(s.config.IncludeParams) > 0 {
			found := false
			for _, include := range s.config.IncludeParams {
				if strings.Contains(key, include) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		for _, value := range values {
			if strings.Contains(content, value) {
				resultChan <- ScanResult{
					Severity:    "Medium",
					Description: fmt.Sprintf("Reflected parameter found on %s", page),
					Payload:     fmt.Sprintf("Parameter '%s' is reflected in the response", key),
				}
			}
		}
	}
}
