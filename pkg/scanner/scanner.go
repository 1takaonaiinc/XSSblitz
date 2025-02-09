package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/1takaonaiinc/xss-scanner/pkg/payloadgen"
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

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Scanner struct {
	patterns   []string
	verbose    bool
	predictor  *predictor.Predictor
	config     ScannerConfig
	client     HTTPClient
	payloadGen *payloadgen.Generator
}

// SetClient allows setting a custom HTTP client (primarily for testing)
func (s *Scanner) SetClient(client HTTPClient) {
	s.client = client
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
		patterns:   patterns,
		verbose:    opts.Verbose,
		predictor:  pred,
		config:     config,
		client:     &http.Client{Timeout: time.Duration(opts.TimeoutSeconds) * time.Second},
		payloadGen: payloadgen.NewGenerator(),
	}, nil
}

func (s *Scanner) ScanPages(ctx context.Context, pages []string) ([]ScanResult, error) {
	if len(pages) == 0 {
		return nil, NewScannerError(ErrorTypeInvalidConfig, "no pages provided to scan", nil)
	}

	results := make([]ScanResult, 0)
	semaphore := make(chan struct{}, s.config.MaxConcurrency)
	resultChan := make(chan ScanResult)
	errChan := make(chan error, len(pages))
	done := make(chan struct{})

	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(ctx, time.Duration(s.config.TimeoutSeconds)*time.Second)
	defer cancel()

	// Start worker goroutine to collect results
	go func() {
		defer close(done)
		for {
			select {
			case result, ok := <-resultChan:
				if !ok {
					return
				}
				results = append(results, result)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Error collector
	var scanErrors []error
	var errMu sync.Mutex
	go func() {
		for err := range errChan {
			errMu.Lock()
			scanErrors = append(scanErrors, err)
			errMu.Unlock()
		}
	}()

	// Process pages concurrently
	for _, page := range pages {
		select {
		case <-ctx.Done():
			return results, NewScannerError(ErrorTypeTimeout, "scan timeout exceeded", ctx.Err())
		case semaphore <- struct{}{}:
		}

		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			if err := s.scanPage(ctx, url, resultChan); err != nil {
				select {
				case errChan <- err:
				case <-ctx.Done():
				}
			}
		}(page)
	}

	// Wait for all workers to finish
	go func() {
		wg.Wait()
		close(resultChan)
		close(errChan)
	}()

	// Wait for either completion or context cancellation
	select {
	case <-done:
	case <-ctx.Done():
		return results, NewScannerError(ErrorTypeTimeout, "scan timeout exceeded", ctx.Err())
	}

	if len(scanErrors) > 0 {
		// Combine all errors into a single error message
		var errMsgs []string
		for _, err := range scanErrors {
			errMsgs = append(errMsgs, err.Error())
		}
		return results, NewScannerError(ErrorTypeHTTPRequest, "scanning errors occurred", fmt.Errorf(strings.Join(errMsgs, "; ")))
	}

	return results, nil
}

func (s *Scanner) scanPage(ctx context.Context, page string, resultChan chan<- ScanResult) error {
	// Check if URL should be excluded
	for _, pattern := range s.config.ExcludePatterns {
		if strings.Contains(page, pattern) {
			if s.verbose {
				fmt.Printf("Skipping excluded URL: %s\n", page)
			}
			return nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", page, nil)
	if err != nil {
		return fmt.Errorf("%w: failed to create request for %s: %v", ErrorTypeHTTPRequest, page, err)
	}

	// Add custom headers
	for key, value := range s.config.CustomHeaders {
		req.Header.Add(key, value)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: failed to fetch page %s: %v", ErrorTypeNetworkFailure, page, err)
	}
	defer resp.Body.Close()

	if !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		if s.verbose {
			fmt.Printf("Skipping non-HTML content: %s\n", page)
		}
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%w: failed to read body of %s: %v", ErrorTypeInvalidResponse, page, err)
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

	// Pattern matching with context-aware check
	payloads := s.payloadGen.Generate(content, len(s.patterns))
	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: context cancelled during pattern matching", ErrorTypeTimeout)
		default:
			if strings.Contains(content, payload) {
				select {
				case resultChan <- ScanResult{
					Severity:    "High",
					Description: fmt.Sprintf("Pattern-matched XSS vulnerability on %s", page),
					Payload:     fmt.Sprintf("Found payload: %s", payload),
				}:
				case <-ctx.Done():
					return fmt.Errorf("%w: context cancelled while sending result", ErrorTypeTimeout)
				}
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

	return nil
}
