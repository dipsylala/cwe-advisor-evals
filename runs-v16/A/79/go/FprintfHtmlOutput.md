## Verdict

**Confirmed XSS vulnerability (CWE-79).**

Line 16 writes user-controlled `customerNote` from the query parameter directly into HTML without escaping. An attacker can inject arbitrary HTML and JavaScript by passing malicious input in the `note` query parameter. Line 14 has the same issue with `ticketID`.

## Source

User input enters through:
- `ticketID := r.URL.Query().Get("id")` (line 9)
- `customerNote := r.URL.Query().Get("note")` (line 10)

Both values flow directly into `fmt.Fprintf()` calls that write HTML (lines 14 and 16) without sanitization.

## Fix

Import the `html` package and escape both user inputs before writing them into the HTML response:

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

`html.EscapeString()` converts dangerous characters (`<`, `>`, `"`, `'`, `&`) into their HTML entity equivalents, ensuring that user input is treated as text content rather than executable code. This prevents the browser from interpreting injected `<script>` tags or event handlers as markup.

Both query parameters require escaping because both flow into HTML context. The fix is minimal and applies the standard Go library solution for this pattern: whenever you build HTML strings by concatenation or formatting, escape user-supplied values at the point of insertion.
