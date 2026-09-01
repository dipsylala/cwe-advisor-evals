## Verdict
CWE-79 confirmed. User-supplied query parameters are written directly to HTML output without escaping, allowing script injection.

## Source
`customerNote` and `ticketID` are extracted from URL query parameters at lines 9-10 via `r.URL.Query().Get()`. Both are attacker-controlled.

## Fix
Import `html` from the standard library and escape both parameters before formatting them into HTML:

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
Query parameters are untrusted input. When rendered into HTML, they must be HTML-escaped to prevent breaking out of the current element and injecting script tags. Go's `html.EscapeString()` converts special characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents, preventing interpretation as markup. This applies equally to both `ticketID` (line 14) and `customerNote` (line 16).
