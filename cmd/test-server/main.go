package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			name = "Guest"
		}

		content := fmt.Sprintf(`
		<!DOCTYPE html>
		<html>
		<head>
			<title>Test Page</title>
		</head>
		<body>
			<h1>Welcome, %s!</h1>
			<form action="/submit" method="GET">
				<input type="text" name="search" value="%s">
				<input type="submit" value="Search">
			</form>
			<script>
				// Potentially vulnerable code
				document.write("Last visited: " + localStorage.getItem("lastVisit"));
			</script>
		</body>
		</html>
		`, name, name)

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, content)
	})

	fmt.Println("Test server running on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
