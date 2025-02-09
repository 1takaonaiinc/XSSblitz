package crawler

import (
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// KeywordExtractor handles the extraction of relevant keywords from HTML content
type KeywordExtractor struct {
	commonWords map[string]bool
	patterns    []string
}

// NewKeywordExtractor creates a new KeywordExtractor instance
func NewKeywordExtractor() *KeywordExtractor {
	// Common words to filter out
	commonWords := map[string]bool{
		"the": true, "be": true, "to": true, "of": true, "and": true,
		"a": true, "in": true, "that": true, "have": true, "i": true,
		"it": true, "for": true, "not": true, "on": true, "with": true,
		"he": true, "as": true, "you": true, "do": true, "at": true,
	}

	// XSS detection patterns
	patterns := []string{
		`input`,
		`script`,
		`javascript`,
		`onload`,
		`onerror`,
		`onclick`,
		`onmouseover`,
		`eval`,
		`alert`,
		`document\.cookie`,
		`localStorage`,
		`sessionStorage`,
		`window\.location`,
		`document\.write`,
		`innerHTML`,
		`src=`,
		`data:`,
		`base64`,
		`<svg`,
		`<img`,
		`<iframe`,
	}

	return &KeywordExtractor{
		commonWords: commonWords,
		patterns:    patterns,
	}
}

// ExtractKeywords extracts relevant keywords from HTML content
func (ke *KeywordExtractor) ExtractKeywords(content string) []string {
	// Use both pattern matching and HTML parsing for comprehensive keyword extraction
	patternKeywords := ke.extractFromPatterns(content)
	htmlKeywords := ke.extractFromHTML(content)

	// Merge keywords from both methods
	allKeywords := make(map[string]bool)
	for _, k := range patternKeywords {
		allKeywords[k] = true
	}
	for _, k := range htmlKeywords {
		allKeywords[k] = true
	}

	// Convert to slice
	result := make([]string, 0, len(allKeywords))
	for k := range allKeywords {
		result = append(result, k)
	}

	return result
}

// extractFromPatterns finds matches using XSS-specific patterns
func (ke *KeywordExtractor) extractFromPatterns(content string) []string {
	var keywords []string
	contentLower := strings.ToLower(content)

	for _, pattern := range ke.patterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		matches := re.FindAllString(contentLower, -1)
		for _, match := range matches {
			if !ke.contains(keywords, match) {
				keywords = append(keywords, match)
			}
		}
	}

	return keywords
}

// extractFromHTML parses HTML and extracts keywords from elements and attributes
func (ke *KeywordExtractor) extractFromHTML(content string) []string {
	doc, err := html.Parse(strings.NewReader(content))
	if err != nil {
		return nil
	}

	keywords := make(map[string]bool)
	ke.extractFromNode(doc, keywords)

	result := make([]string, 0, len(keywords))
	for k := range keywords {
		result = append(result, k)
	}

	return result
}

func (ke *KeywordExtractor) extractFromNode(n *html.Node, keywords map[string]bool) {
	if n.Type == html.ElementNode {
		// Extract from element attributes
		for _, attr := range n.Attr {
			ke.processText(attr.Val, keywords)
			if attr.Key == "id" || attr.Key == "name" || attr.Key == "class" {
				ke.processText(attr.Key, keywords)
			}
		}

		// Extract input names and types
		if n.Data == "input" {
			for _, attr := range n.Attr {
				if attr.Key == "name" || attr.Key == "type" {
					ke.processText(attr.Val, keywords)
				}
			}
		}

		// Extract form actions
		if n.Data == "form" {
			for _, attr := range n.Attr {
				if attr.Key == "action" {
					ke.processText(attr.Val, keywords)
				}
			}
		}
	} else if n.Type == html.TextNode {
		ke.processText(n.Data, keywords)
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		ke.extractFromNode(c, keywords)
	}
}

func (ke *KeywordExtractor) processText(text string, keywords map[string]bool) {
	// Clean and normalize text
	text = strings.ToLower(text)

	// Remove special characters and digits
	re := regexp.MustCompile(`[^a-z\s]`)
	text = re.ReplaceAllString(text, " ")

	// Split into words
	words := strings.Fields(text)

	// Add relevant words to keywords map
	for _, word := range words {
		if len(word) > 2 && !ke.commonWords[word] {
			keywords[word] = true
		}
	}
}

// AddPattern adds a new pattern to the extractor
func (ke *KeywordExtractor) AddPattern(pattern string) {
	if !ke.contains(ke.patterns, pattern) {
		ke.patterns = append(ke.patterns, pattern)
	}
}

// GetPatterns returns the current patterns
func (ke *KeywordExtractor) GetPatterns() []string {
	return ke.patterns
}

// Helper function to check if slice contains string
func (ke *KeywordExtractor) contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
