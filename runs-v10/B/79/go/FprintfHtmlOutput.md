## Verdict

Exploitable. Untrusted URL query parameter flows directly into HTML output without escaping.

## Source

Line 10: `customerNote := r.URL.Query().Get("note")`

## Fix

**Vulnerable code (lines 8-18):**
```go
func ticketStatusHandler(w http.ResponseWriter, r *http.Request) {
	ticketID := r.URL.Query().Get("id")
	customerNote := r.URL.Query().Get("note")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body>")
	fmt.Fprintf(w, "<h2>Ticket %s</h2>", ticketID)
	fmt.Fprintf(w, "<p>Customer note: %s</p>", customerNote)  // XSS sink
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

func ticketStatusHandler(w http.ResponseWriter, r *http.Request) {
	ticketID := r.URL.Query().Get("id")
	customerNote := r.URL.Query().Get("note")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	tmpl := template.Must(template.New("ticket").Parse(`<html><body>
<h2>Ticket {{.ID}}</h2>
<p>Customer note: {{.Note}}</p>
</body></html>`))

	data := struct {
		ID   string
		Note string
	}{
		ID:   ticketID,
		Note: customerNote,
	}

	tmpl.Execute(w, data)
}

func main() {
	http.HandleFunc("/support/ticket", ticketStatusHandler)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

The fix replaces unsafe string concatenation with `html/template`, which provides context-aware automatic escaping. When `{{.ID}}` and `{{.Note}}` are rendered in HTML body context, the template engine automatically escapes special characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents, preventing injected scripts or HTML from executing. This eliminates the XSS vector by ensuring untrusted input remains data rather than executable code. The template struct ensures variables are bound cleanly, and using `template.Must()` with a constant template provides fail-fast behavior for any parsing errors.

## Behaviour changes

- **Import change:** Removed `"fmt"`, added `"html/template"` (security-critical: `html/template` provides escaping; `text/template` does not)
- **Output method:** Replaced five separate `fmt.Fprintf` calls with single `tmpl.Execute()` call (consolidates HTML generation into one template for consistent context-aware escaping)
- **Data binding:** Changed from format arguments to template data struct (required for template binding and context-aware escaping)
- **Return handling:** `template.Execute()` return value is not checked, matching original behavior where `fmt.Fprintf` errors were also silently discarded
