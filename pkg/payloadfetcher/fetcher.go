package payloadfetcher

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

type PayloadFetcher struct {
	url string
}

func NewPayloadFetcher(url string) *PayloadFetcher {
	return &PayloadFetcher{
		url: url,
	}
}

func (pf *PayloadFetcher) FetchPayloads() ([]string, error) {
	// Get the content
	resp, err := http.Get(pf.url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch URL: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	content := string(body)

	// Extract payloads using regex patterns
	var payloads []string

	// Common XSS payload patterns
	patterns := []string{
		`<script[^>]*>[^<]*</script>`,
		`javascript:[^\s'"]+`,
		`onerror=['"][^'"]*['"]`,
		`onload=['"][^'"]*['"]`,
		`onclick=['"][^'"]*['"]`,
		`onmouseover=['"][^'"]*['"]`,
		`<img[^>]+src=['"][^'"]*['"]`,
		`<iframe[^>]+src=['"][^'"]*['"]`,
		`alert\([^)]*\)`,
		`prompt\([^)]*\)`,
		`confirm\([^)]*\)`,
		`eval\([^)]*\)`,
	}

	// Extract code blocks which often contain payloads
	codeBlockRegex := regexp.MustCompile(`(?s)<pre[^>]*>(.*?)</pre>`)
	codeBlocks := codeBlockRegex.FindAllStringSubmatch(content, -1)

	for _, block := range codeBlocks {
		if len(block) > 1 {
			// Clean the code block content
			cleanCode := strings.TrimSpace(block[1])

			// Skip if it looks like explanatory text rather than a payload
			if len(cleanCode) > 500 || strings.Count(cleanCode, " ") > 20 {
				continue
			}

			// Process each pattern
			for _, pattern := range patterns {
				re := regexp.MustCompile(pattern)
				matches := re.FindAllString(cleanCode, -1)
				for _, match := range matches {
					// Clean and normalize the payload
					payload := strings.TrimSpace(match)
					if payload != "" && !containsPayload(payloads, payload) {
						payloads = append(payloads, payload)
					}
				}
			}

			// If the code block itself looks like a complete payload, add it
			if isLikelyPayload(cleanCode) {
				payloads = append(payloads, cleanCode)
			}
		}
	}

	return payloads, nil
}

func containsPayload(payloads []string, newPayload string) bool {
	for _, p := range payloads {
		if p == newPayload {
			return true
		}
	}
	return false
}

func isLikelyPayload(code string) bool {
	// Check if the code block looks like a complete XSS payload
	indicators := []string{
		"<script",
		"javascript:",
		"alert(",
		"eval(",
		"onerror=",
		"onload=",
		"<img",
		"<iframe",
	}

	code = strings.ToLower(code)

	for _, indicator := range indicators {
		if strings.Contains(code, indicator) {
			// Additional validation to avoid false positives
			if len(code) < 500 && strings.Count(code, " ") < 20 {
				return true
			}
		}
	}

	return false
}
