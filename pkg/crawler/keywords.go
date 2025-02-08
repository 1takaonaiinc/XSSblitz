package crawler

import (
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// KeywordExtractor handles the extraction of relevant keywords from HTML content
type KeywordExtractor struct {
	commonWords map[string]bool
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

	return &KeywordExtractor{
		commonWords: commonWords,
	}
}

// ExtractKeywords extracts relevant keywords from HTML content
func (ke *KeywordExtractor) ExtractKeywords(content string) []string {
	doc, err := html.Parse(strings.NewReader(content))
	if err != nil {
		return nil
	}

	keywords := make(map[string]bool)
	ke.extractFromNode(doc, keywords)

	// Convert keywords map to slice
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
