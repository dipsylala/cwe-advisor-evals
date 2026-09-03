## Verdict

Confirmed. The code passes unsanitized user input directly into HTML output, enabling stored or reflected cross-site scripting (XSS).

## Source

```go
func ticketStatusHandler(w http.ResponseWriter, r *http.Request) {
	ticketID := r.URL.Query().Get("id")
	customerNote := r.URL.Query().Get("note")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body>")
	fmt.Fprintf(w, "<h2>Ticket %s</h2>", ticketID)
	// VULNERABLE: no escaping of customerNote
	fmt.Fprintf(w, "<p>Customer note: %s</p>", customerNote)
	fmt.Fprintf(w, "</body></html>")
}
```

Both `ticketID` and `customerNote` are extracted from URL query parameters and written directly into HTML via `fmt.Fprintf()` without any escaping.

## Fix

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

The vulnerability occurs because user-controlled query parameters are rendered directly into HTML context without encoding. An attacker supplying a `note` parameter like `<script>alert('XSS')</script>` would have the script injected and executed in the browser.

The fix wraps both user inputs with `html.EscapeString()` from Go's standard `html` package. This function converts dangerous characters (`<`, `>`, `"`, `&`, etc.) to their HTML entity equivalents (`&lt;`, `&gt;`, `&quot;`, `&amp;`), preventing the browser from interpreting them as HTML markup. With this applied:
- Input: `<script>alert('XSS')</script>`
- Output in HTML: `&lt;script&gt;alert('XSS')&lt;/script&gt;`
- Browser renders: the literal text, not executable code

This is the primary defense for XSS in HTML contexts: context-appropriate output encoding. Use `html.EscapeString()` whenever rendering user data into HTML, unless using a template engine (like `html/template`) that applies escaping automatically.
