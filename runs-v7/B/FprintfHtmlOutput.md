## Verdict

Exploitable. Untrusted query parameter `note` flows directly into HTML output without encoding.

## Source

`customerNote := r.URL.Query().Get("note")` at line 10. The value originates from the URL query string, making it attacker-controlled.

## Fix

Replace `fmt.Fprintf` string concatenation with `html/template`, which automatically applies context-aware HTML entity escaping:

**Vulnerable code:**
```go
func ticketStatusHandler(w http.ResponseWriter, r *http.Request) {
	ticketID := r.URL.Query().Get("id")
	customerNote := r.URL.Query().Get("note")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body>")
	fmt.Fprintf(w, "<h2>Ticket %s</h2>", ticketID)
	// CWE-79: Unescaped output
	fmt.Fprintf(w, "<p>Customer note: %s</p>", customerNote)
	fmt.Fprintf(w, "</body></html>")
}
```

**Fixed code:**
```go
package main

import (
	"html/template"
	"net/http"
)

var ticketTemplate = template.Must(template.New("ticket").Parse(`
<html><body>
<h2>Ticket {{.TicketID}}</h2>
<p>Customer note: {{.CustomerNote}}</p>
</body></html>
`))

func ticketStatusHandler(w http.ResponseWriter, r *http.Request) {
	ticketID := r.URL.Query().Get("id")
	customerNote := r.URL.Query().Get("note")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	
	data := struct {
		TicketID     string
		CustomerNote string
	}{
		TicketID:     ticketID,
		CustomerNote: customerNote,
	}
	
	ticketTemplate.Execute(w, data)
}

func main() {
	http.HandleFunc("/support/ticket", ticketStatusHandler)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

The fix replaces `fmt.Fprintf` writes with `html/template`, which automatically escapes values when they are rendered into HTML body context. When `{{.CustomerNote}}` is evaluated, `html/template` converts characters like `<`, `>`, `&`, and quotes into their HTML entity forms (`&lt;`, `&gt;`, `&amp;`, etc.), preventing injected scripts from executing. The template is parsed once and reused for every request, avoiding the concatenation-based approach that leaves values unescaped.

## Behaviour changes

The response structure and content remain identical for benign input. The primary behaviour change is that special HTML characters in user input are now encoded: an attacker's payload like `<script>alert('xss')</script>` is rendered as literal text in the HTML, not as an executable script tag. The HTTP header `Content-Type: text/html; charset=utf-8` is set identically. No output is discarded; all values flow through the template. The template is defined at module scope to avoid parsing overhead on every request.
