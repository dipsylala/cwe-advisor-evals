## Verdict

Exploitable. Untrusted user input from `r.URL.Query().Get("note")` flows directly into HTML output via `fmt.Fprintf` without encoding, allowing arbitrary HTML/JavaScript injection.

## Source

`r.URL.Query().Get("note")` - URL query parameter `note` (line 10)

## Fix

**Vulnerable code:**
```go
func ticketStatusHandler(w http.ResponseWriter, r *http.Request) {
	ticketID := r.URL.Query().Get("id")
	customerNote := r.URL.Query().Get("note")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body>")
	fmt.Fprintf(w, "<h2>Ticket %s</h2>", ticketID)
	fmt.Fprintf(w, "<p>Customer note: %s</p>", customerNote)  // Sink: no encoding
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
	
	tmpl := template.Must(template.New("ticket").Parse(`
		<html><body>
		<h2>Ticket {{.TicketID}}</h2>
		<p>Customer note: {{.Note}}</p>
		</body></html>
	`))
	
	data := struct {
		TicketID string
		Note     string
	}{
		TicketID: ticketID,
		Note:     customerNote,
	}
	
	tmpl.Execute(w, data)
}

func main() {
	http.HandleFunc("/support/ticket", ticketStatusHandler)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

The fix replaces unsafe string concatenation with `html/template`, which provides automatic context-aware HTML entity encoding. Both `ticketID` and `customerNote` are passed into a data struct and rendered via template actions `{{.TicketID}}` and `{{.Note}}`. The html/template engine automatically escapes all data fields, converting HTML metacharacters such as `<` to `&lt;`, `>` to `&gt;`, `&` to `&amp;`, and `"` to `&#34;`. This prevents injected JavaScript and arbitrary HTML from executing in the browser. The template approach ensures escaping is applied consistently across all data values, and the same template pattern scales safely to other contexts (attributes, JavaScript strings, URLs) without requiring manual escaper selection.

## Behaviour changes

- Import changes: `fmt` is removed, `html/template` is added
- The HTML is now generated via template execution instead of sequential `fmt.Fprintf` writes
- Data is passed through a struct instead of being concatenated into strings
- `template.Execute()` writes to `w` directly, preserving the same output destination
- `template.Execute()` may return an error; the original code cannot check this as `fmt.Fprintf` was used - error handling should be added in production: `if err := tmpl.Execute(w, data); err != nil { http.Error(w, "template error", http.StatusInternalServerError) }`
- All output retains the same HTML structure and renders identically for legitimate input
- Malicious payloads like `<script>alert('XSS')</script>` are rendered as escaped text: `&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;`
