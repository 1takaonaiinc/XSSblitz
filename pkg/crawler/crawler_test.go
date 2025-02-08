package crawler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCrawler(t *testing.T) {
	// Create test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`
<!DOCTYPE html>
<html>
<head><title>Test Page</title></head>
<body>
<form action="/submit">
<input type="text" name="search">
<input type="text" name="username">
</form>
<a href="/page1">Link 1</a>
<a href="/page2">Link 2</a>
<script>
document.cookie = "test=value";
localStorage.setItem("key", "value");
</script>
</body>
</html>
`))
	}))
	defer ts.Close()

	c := NewCrawler()
	c.SetMaxDepth(2)

	pages, keywords, err := c.Crawl(ts.URL)
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}

	// Check if pages were found
	if len(pages) == 0 {
		t.Error("No pages found")
	}

	// Check if keywords were extracted
	if len(keywords) == 0 {
		t.Error("No keywords extracted")
	}

	// Check for specific keywords
	expectedKeywords := []string{"search", "username", "document", "cookie", "localStorage"}
	for _, expected := range expectedKeywords {
		found := false
		for _, keyword := range keywords {
			if keyword == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected keyword %q not found", expected)
		}
	}

	// Check URL extraction
	foundPages := make(map[string]bool)
	for _, page := range pages {
		foundPages[page] = true
	}

	expectedURLs := []string{
		ts.URL + "/page1",
		ts.URL + "/page2",
	}

	for _, url := range expectedURLs {
		if !foundPages[url] {
			t.Errorf("Expected URL %q not found", url)
		}
	}
}
