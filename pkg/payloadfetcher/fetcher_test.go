package payloadfetcher

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPayloadFetcher(t *testing.T) {
	// Create test server with mock XSS cheat sheet content
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`
<!DOCTYPE html>
<html>
<body>
<h1>XSS Cheat Sheet</h1>
<pre><code>&lt;script&gt;alert(1)&lt;/script&gt;</code></pre>
<pre><code>javascript:alert(1)</code></pre>
<pre><code>&lt;img src=x onerror=alert(1)&gt;</code></pre>
<pre><code>Some explanatory text that should not be detected as a payload because it's too long and contains many spaces</code></pre>
<pre><code>&lt;iframe src="javascript:alert(2)"&gt;</code></pre>
<script>
// This should be detected
alert(document.cookie)
</script>
</body>
</html>
`))
	}))
	defer ts.Close()

	// Create fetcher with test server URL
	fetcher := NewPayloadFetcher(ts.URL)

	// Fetch payloads
	payloads, err := fetcher.FetchPayloads()
	if err != nil {
		t.Fatalf("Failed to fetch payloads: %v", err)
	}

	// Check if payloads were found
	if len(payloads) == 0 {
		t.Error("No payloads found")
	}

	// Expected XSS payloads that should be detected
	expectedPayloads := []string{
		"<script>alert(1)</script>",
		"javascript:alert(1)",
		"<img src=x onerror=alert(1)>",
		"<iframe src=\"javascript:alert(2)\">",
		"alert(document.cookie)",
	}

	// Check if all expected payloads were found
	for _, expected := range expectedPayloads {
		found := false
		for _, payload := range payloads {
			if payload == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected payload not found: %s", expected)
		}
	}

	// Verify that explanatory text was not included as payload
	for _, payload := range payloads {
		if len(payload) > 500 || payload == "Some explanatory text that should not be detected as a payload because it's too long and contains many spaces" {
			t.Error("Explanatory text was incorrectly identified as payload")
		}
	}

	// Test duplicate handling
	if len(payloads) != len(expectedPayloads) {
		t.Errorf("Expected %d unique payloads, got %d", len(expectedPayloads), len(payloads))
	}
}

func TestIsLikelyPayload(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{
			input:    "<script>alert(1)</script>",
			expected: true,
		},
		{
			input:    "This is just some regular text",
			expected: false,
		},
		{
			input:    "javascript:alert(document.cookie)",
			expected: true,
		},
		{
			input:    "<img src=x onerror=alert(1)>",
			expected: true,
		},
		{
			input:    strings.Repeat("a", 600), // Too long
			expected: false,
		},
		{
			input:    "This text has too many spaces " + strings.Repeat("word ", 20),
			expected: false,
		},
	}

	for _, test := range tests {
		result := isLikelyPayload(test.input)
		if result != test.expected {
			t.Errorf("isLikelyPayload(%q) = %v; want %v", test.input, result, test.expected)
		}
	}
}
