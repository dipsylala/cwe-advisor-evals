## Verdict

Exploitable

## Source

Untrusted user input from URL query parameters: `r.URL.Query().Get("id")` and `r.URL.Query().Get("note")`, both read at lines 9-10.

## Fix

### File: FprintfHtmlOutput.go

```go
package main

import (
	"html/template"
	"log"
	"net/http"
)

func ticketStatusHandler(w http.ResponseWriter, r *http.Request) {
	ticketID := r.URL.Query().Get("id")
	customerNote := r.URL.Query().Get("note")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	tmpl, err := template.New("ticket").Parse(`<html><body><h2>Ticket {{.ID}}</h2><p>Customer note: {{.Note}}</p></body></html>`)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	data := struct {
		ID   string
		Note string
	}{
		ID:   ticketID,
		Note: customerNote,
	}

	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err)
	}
}

func main() {
	http.HandleFunc("/support/ticket", ticketStatusHandler)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

The vulnerability allows reflected XSS because untrusted query parameters are written directly into HTML using `fmt.Fprintf` without any escaping. An attacker can craft a malicious URL like `?note=<script>alert('XSS')</script>` to inject executable JavaScript into the page.

The fix replaces the unsafe `fmt.Fprintf` pattern with `html/template`, which performs context-aware output escaping automatically. Both `ticketID` and `customerNote` are now passed into the template data struct and rendered using `{{.ID}}` and `{{.Note}}` placeholders. The `html/template` package escapes these values for safe insertion in HTML body text, converting characters like `<`, `>`, and `&` into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`). This ensures that any HTML or JavaScript in the input is rendered as literal text, not executed.

## Behaviour changes

- Added imports: `html/template` and `log` (required for template handling and error logging)
- Changed from multiple `fmt.Fprintf` writes to a single `html/template` execution
- Added error handling for template parsing with `http.Error` to return an HTTP 500 response on template errors
- Added error logging for template execution failures
- Content-Type header remains `text/html; charset=utf-8`, preserving the original intent
- The HTML structure is now defined in a single parsed template string rather than multiple concatenated calls
- HTML special characters in `ticketID` and `customerNote` are now properly escaped by `html/template` instead of being rendered as raw HTML

Verification: Code compiled successfully with `go build` and `go vet` with no errors or warnings.
