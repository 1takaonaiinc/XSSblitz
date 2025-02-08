package crawler

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/net/html"
)

type Crawler struct {
	keywordExtractor *KeywordExtractor
	maxDepth         int
}

func NewCrawler() *Crawler {
	return &Crawler{
		keywordExtractor: NewKeywordExtractor(),
		maxDepth:         2, // Default depth
	}
}

func (c *Crawler) SetMaxDepth(depth int) {
	c.maxDepth = depth
}

func (c *Crawler) Crawl(url string) ([]string, []string, error) {
	visited := make(map[string]bool)
	var pages []string
	var allKeywords []string

	err := c.crawlRecursive(url, 0, visited, &pages, &allKeywords)
	if err != nil {
		return nil, nil, err
	}

	return pages, allKeywords, nil
}

func (c *Crawler) crawlRecursive(url string, depth int, visited map[string]bool, pages *[]string, keywords *[]string) error {
	if depth >= c.maxDepth || visited[url] {
		return nil
	}
	visited[url] = true

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch URL %s: %v", url, err)
	}
	defer resp.Body.Close()

	// Extract keywords from the page content
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read body from %s: %v", url, err)
	}
	bodyContent := string(bodyBytes)
	pageKeywords := c.keywordExtractor.ExtractKeywords(bodyContent)
	*keywords = append(*keywords, pageKeywords...)

	// Reset the response body for HTML parsing
	resp.Body = io.NopCloser(strings.NewReader(bodyContent))

	z := html.NewTokenizer(resp.Body)
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return nil
		case html.StartTagToken, html.SelfClosingTagToken:
			t := z.Token()
			if t.Data == "a" {
				for _, a := range t.Attr {
					if a.Key == "href" {
						link := a.Val
						if strings.HasPrefix(link, "/") {
							link = url + link
						}
						if !visited[link] {
							*pages = append(*pages, link)
							if err := c.crawlRecursive(link, depth+1, visited, pages, keywords); err != nil {
								// Log error but continue crawling
								fmt.Printf("Error crawling %s: %v\n", link, err)
							}
						}
					}
				}
			}
		}
	}
}
