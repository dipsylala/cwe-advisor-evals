## Verdict

Real vulnerability. The `customerNote` variable originates from user input (`r.URL.Query().Get("note")`) and is written directly into HTML output via `fmt.Fprintf()` without escaping. An attacker can inject arbitrary HTML and JavaScript by passing `note=<script>alert('xss')</script>` in the query string.

## Source

Line 11: `customerNote := r.URL.Query().Get("note")` — untrusted query parameter.
Line 16: `fmt.Fprintf(w, "<p>Customer note: %s</p>", customerNote)` — sink where unescaped user input reaches HTML output.

## Fix

### File: FprintfHtmlOutput.go

```go
package main

import (
	"fmt"
	"html"
	"net/http"
)

func ticketStatusHandler(w http.ResponseWriter, r *http.Request) {
	ticketID := r.URL.Query().Get("id")
	customerNote := r.URL.Query().Get("note")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body>")
	fmt.Fprintf(w, "<h2>Ticket %s</h2>", html.EscapeString(ticketID))
	fmt.Fprintf(w, "<p>Customer note: %s</p>", html.EscapeString(customerNote))
	fmt.Fprintf(w, "</body></html>")
}

func main() {
	http.HandleFunc("/support/ticket", ticketStatusHandler)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

Import Go's standard library `html` package and apply `html.EscapeString()` to both user-controlled variables before writing them to HTML output. The function escapes `<`, `>`, `"`, `'`, and `&` to their HTML entity equivalents (`&lt;`, `&gt;`, `&quot;`, `&#39;`, `&amp;`), preventing the browser from interpreting them as markup or script tags. This is the primary XSS defence in Go web handlers that use `fmt.Fprintf` to generate HTML responses.

