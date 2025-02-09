package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ErrorType represents types of scanner errors
type ErrorType int

const (
	ErrorTypeInvalidConfig ErrorType = iota
	ErrorTypeHTTPRequest
	ErrorTypeNetworkFailure
	ErrorTypeInvalidResponse
	ErrorTypeMLPrediction
	ErrorTypeTimeout
)

// ScannerError represents a scanner-specific error
type ScannerError struct {
	Type    ErrorType
	Message string
	Err     error
}

func (e *ScannerError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *ScannerError) Unwrap() error {
	return e.Err
}

// NewScannerError creates a new ScannerError
func NewScannerError(errType ErrorType, message string, err error) *ScannerError {
	return &ScannerError{
		Type:    errType,
		Message: message,
		Err:     err,
	}
}

type Config struct {
	CustomHeaders    map[string]string
	TimeoutSeconds   int
	MaxConcurrency   int
	ExcludePatterns  []string
	IncludeParams    []string
	InjectedPayloads []string // Added field for payload injection
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type ScanResult struct {
	URL         string
	Severity    string
	Description string
	Payload     string
	Timestamp   time.Time
}

// Scanner represents the core scanning service
type Scanner struct {
	config  Config
	client  HTTPClient
	results chan ScanResult
	wg      sync.WaitGroup
	mu      sync.Mutex
}

func NewScanner(cfg Config) *Scanner {
	if cfg.TimeoutSeconds == 0 {
		cfg.TimeoutSeconds = 30
	}
	if cfg.MaxConcurrency == 0 {
		cfg.MaxConcurrency = 5
	}

	return &Scanner{
		config:  cfg,
		client:  &http.Client{Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second},
		results: make(chan ScanResult, 100),
	}
}

func (s *Scanner) SetClient(client HTTPClient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.client = client
}

// StartScan initiates the scanning process with context support
func (s *Scanner) StartScan(ctx context.Context, pages []string) (<-chan ScanResult, error) {
	if len(pages) == 0 {
		return nil, NewScannerError(ErrorTypeInvalidConfig, "no pages provided to scan", nil)
	}

	resultsChan := make(chan ScanResult, len(pages))
	semaphore := make(chan struct{}, s.config.MaxConcurrency)
	errChan := make(chan error, 1)

	// Use WaitGroup for worker management
	var wg sync.WaitGroup

	// Start worker goroutines
	for _, page := range pages {
		select {
		case <-ctx.Done():
			return resultsChan, NewScannerError(ErrorTypeTimeout, "scan timeout exceeded", ctx.Err())
		default:
			wg.Add(1)
			go func(url string) {
				defer wg.Done()

				select {
				case semaphore <- struct{}{}: // Acquire with timeout
					defer func() { <-semaphore }() // Release
					if err := s.scanPage(ctx, url, resultsChan); err != nil {
						select {
						case errChan <- err:
						case <-ctx.Done():
						}
					}
				case <-ctx.Done():
					return
				}
			}(page)
		}
	}

	// Close results channel when all workers are done or context is cancelled
	go func() {
		// Wait for either completion or cancellation
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-ctx.Done():
		}

		// Cleanup
		close(resultsChan)
		close(errChan)
	}()

	// Check for errors
	select {
	case err := <-errChan:
		if err != nil {
			return resultsChan, err
		}
	default:
	}

	return resultsChan, nil
}

func (s *Scanner) scanPage(ctx context.Context, page string, resultsChan chan<- ScanResult) error {
	// Check if URL should be excluded
	for _, pattern := range s.config.ExcludePatterns {
		if strings.Contains(page, pattern) {
			return nil
		}
	}

	// First scan the original URL
	if err := s.scanURL(ctx, page, resultsChan); err != nil {
		return err
	}

	// Then try each payload if configured
	if len(s.config.InjectedPayloads) > 0 {
		for _, payload := range s.config.InjectedPayloads {
			// Create a test URL with the payload
			testURL := s.injectPayload(page, payload)
			if err := s.scanURL(ctx, testURL, resultsChan); err != nil {
				fmt.Printf("Error testing payload on %s: %v\n", page, err)
				continue
			}
		}
	}

	return nil
}

func (s *Scanner) scanURL(ctx context.Context, url string, resultsChan chan<- ScanResult) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add custom headers
	for key, value := range s.config.CustomHeaders {
		req.Header.Add(key, value)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch page: %w", err)
	}
	defer resp.Body.Close()

	if !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read body: %w", err)
	}

	select {
	case <-ctx.Done():
		return NewScannerError(ErrorTypeTimeout, "scan timeout during response processing", ctx.Err())
	default:
		// Check for reflected parameters
		s.checkReflectedParameters(ctx, url, string(body), resp.Request.URL.Query(), resultsChan)
	}

	return nil
}

func (s *Scanner) injectPayload(url, payload string) string {
	// Check if URL already has parameters
	if strings.Contains(url, "?") {
		return url + "&test=" + payload
	}
	return url + "?test=" + payload
}

func (s *Scanner) checkReflectedParameters(ctx context.Context, page, content string, params map[string][]string, resultsChan chan<- ScanResult) {
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
				select {
				case resultsChan <- ScanResult{
					URL:         page,
					Severity:    "Medium",
					Description: "Reflected parameter found",
					Payload:     fmt.Sprintf("Parameter '%s' is reflected in the response", key),
					Timestamp:   time.Now(),
				}:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}
