package scanner

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// MockHTTPClient implements custom response handling for tests
type MockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}

// mockResponse creates a mock HTTP response
func mockResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
		Request:    &http.Request{URL: &url.URL{}},
	}
}

func TestNewScanner(t *testing.T) {
	opts := Options{
		Patterns:       []string{"<script>alert(1)</script>"},
		Verbose:        true,
		MLModel:        "../../models/default.json",
		MLThreshold:    0.7,
		ExcludeUrls:    []string{},
		IncludeParams:  []string{},
		TimeoutSeconds: 30,
		MaxConcurrency: 5,
		Headers:        map[string]string{},
	}

	s, err := NewScanner(opts)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	if s == nil {
		t.Fatal("Scanner should not be nil")
	}

	if s.payloadGen == nil {
		t.Error("PayloadGenerator should be initialized")
	}

	if len(s.patterns) == 0 {
		t.Error("Scanner should have at least one pattern")
	}
}

func TestScanPagesErrors(t *testing.T) {
	tests := []struct {
		name        string
		pages       []string
		mockResp    *http.Response
		mockErr     error
		wantErrType ErrorType
	}{
		{
			name:        "Empty pages list",
			pages:       []string{},
			wantErrType: ErrorTypeInvalidConfig,
		},
		{
			name:        "Network failure",
			pages:       []string{"http://example.com"},
			mockErr:     errors.New("connection refused"),
			wantErrType: ErrorTypeNetworkFailure,
		},
		{
			name:  "Invalid response",
			pages: []string{"http://example.com"},
			mockResp: &http.Response{
				StatusCode: 500,
				Body:       io.NopCloser(bytes.NewBufferString("server error")),
				Header:     make(http.Header),
			},
			wantErrType: ErrorTypeHTTPRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			mockClient := &MockHTTPClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					if tt.mockErr != nil {
						return nil, tt.mockErr
					}
					return tt.mockResp, nil
				},
			}

			s, _ := NewScanner(Options{Verbose: true})
			s.SetClient(mockClient)

			_, err := s.ScanPages(ctx, tt.pages)
			if err == nil {
				t.Error("Expected error but got none")
				return
			}

			scanErr, ok := err.(*ScannerError)
			if !ok {
				t.Errorf("Expected ScannerError but got %T", err)
				return
			}

			if scanErr.Type != tt.wantErrType {
				t.Errorf("Got error type %v, want %v", scanErr.Type, tt.wantErrType)
			}
		})
	}
}

func TestDynamicPayloadGeneration(t *testing.T) {
	mockResponses := []struct {
		url     string
		content string
		want    bool
	}{
		{
			url:     "http://example.com/form",
			content: `<form><input type="text" onerror="alert(1)"></form>`,
			want:    true,
		},
		{
			url:     "http://example.com/js",
			content: `<script>var x='user_input';</script>`,
			want:    true,
		},
		{
			url:     "http://example.com/safe",
			content: `<div>Hello World</div>`,
			want:    false,
		},
	}

	for _, resp := range mockResponses {
		t.Run("Testing "+resp.url, func(t *testing.T) {
			ctx := context.Background()
			mockClient := &MockHTTPClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					response := mockResponse(200, resp.content)
					response.Header.Set("Content-Type", "text/html")
					return response, nil
				},
			}

			s, _ := NewScanner(Options{})
			s.SetClient(mockClient)

			results, err := s.ScanPages(ctx, []string{resp.url})
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			foundVuln := len(results) > 0
			if foundVuln != resp.want {
				t.Errorf("URL %s: got vulnerability = %v, want %v", resp.url, foundVuln, resp.want)
			}
		})
	}
}

func TestParameterReflection(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			paramValue := req.URL.Query().Get("test")
			resp := mockResponse(200, "<div>"+paramValue+"</div>")
			resp.Header.Set("Content-Type", "text/html")
			resp.Request = req
			return resp, nil
		},
	}

	opts := Options{
		Verbose:        false,
		MLModel:        "../../models/default.json",
		TimeoutSeconds: 5,
		MaxConcurrency: 2,
		IncludeParams:  []string{"test"},
	}

	s, err := NewScanner(opts)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	s.SetClient(mockClient)
	pages := []string{"http://example.com?test=reflected"}
	results, err := s.ScanPages(ctx, pages)
	if err != nil {
		t.Fatalf("Unexpected error during scan: %v", err)
	}

	if len(results) == 0 {
		t.Error("Expected to find reflected parameter but found none")
	}

	found := false
	for _, result := range results {
		if strings.Contains(result.Description, "Reflected parameter") {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected to find reflected parameter result")
	}
}

func TestExcludePatterns(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			resp := mockResponse(200, "<div>test</div>")
			resp.Header.Set("Content-Type", "text/html")
			return resp, nil
		},
	}

	opts := Options{
		Patterns:       []string{"<script>"},
		ExcludeUrls:    []string{"exclude"},
		TimeoutSeconds: 5,
		MaxConcurrency: 2,
	}

	s, err := NewScanner(opts)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	s.SetClient(mockClient)
	pages := []string{"http://example.com/exclude/page"}
	results, err := s.ScanPages(ctx, pages)
	if err != nil {
		t.Fatalf("Unexpected error during scan: %v", err)
	}

	if len(results) > 0 {
		t.Error("Expected excluded URL to be skipped")
	}
}

func TestConcurrencyLimit(t *testing.T) {
	maxConcurrent := 2
	pageCount := 5
	processed := 0

	concurrentOps := make(chan struct{}, maxConcurrent)
	maxObserved := 0

	mockClient := &MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			// Track concurrent operations
			concurrentOps <- struct{}{}
			currentConcurrent := len(concurrentOps)
			if currentConcurrent > maxObserved {
				maxObserved = currentConcurrent
			}

			// Simulate work
			time.Sleep(100 * time.Millisecond)
			<-concurrentOps
			processed++

			resp := mockResponse(200, "<div>test</div>")
			resp.Header.Set("Content-Type", "text/html")
			return resp, nil
		},
	}

	opts := Options{
		MaxConcurrency: maxConcurrent,
		TimeoutSeconds: 5,
	}

	s, err := NewScanner(opts)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	s.SetClient(mockClient)
	ctx := context.Background()
	pages := make([]string, pageCount)
	for i := 0; i < pageCount; i++ {
		pages[i] = "http://example.com"
	}

	results, err := s.ScanPages(ctx, pages)
	if err != nil {
		t.Fatalf("Unexpected error during scan: %v", err)
	}

	// Verify all pages were processed
	if processed != pageCount {
		t.Errorf("Expected %d pages to be processed, got %d", pageCount, processed)
	}

	// Verify we got the expected number of scan results
	if len(results) != pageCount {
		t.Errorf("Expected %d scan results, got %d", pageCount, len(results))
	}

	// Verify concurrency limit was respected
	if maxObserved > maxConcurrent {
		t.Errorf("Max concurrent operations (%d) exceeded limit (%d)", maxObserved, maxConcurrent)
	}
}

func TestTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	mockClient := &MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			time.Sleep(200 * time.Millisecond) // Longer than timeout
			return mockResponse(200, "<div>test</div>"), nil
		},
	}

	s, _ := NewScanner(Options{MaxConcurrency: 1, TimeoutSeconds: 5})
	s.SetClient(mockClient)

	_, err := s.ScanPages(ctx, []string{"http://example.com"})
	if err == nil {
		t.Fatal("Expected timeout error but got none")
	}

	scanErr, ok := err.(*ScannerError)
	if !ok {
		t.Fatalf("Expected ScannerError but got %T", err)
	}

	if scanErr.Type != ErrorTypeTimeout {
		t.Errorf("Got error type %v, want %v", scanErr.Type, ErrorTypeTimeout)
	}
}
