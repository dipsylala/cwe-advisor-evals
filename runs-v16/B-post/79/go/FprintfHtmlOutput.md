## Verdict

Exploitable. Untrusted user input from a query parameter is directly interpolated into HTML content without encoding, allowing arbitrary JavaScript execution.

## Source

Line 10: `customerNote := r.URL.Query().Get("note")` — untrusted query parameter.

Data flows from the HTTP request query string directly to the response without validation or encoding.

## Fix

**Vulnerable code (line 16):**

```go
fmt.Fprintf(w, "<p>Customer note: %s</p>", customerNote)
```

**Fixed code:**

Replace the entire handler with `html/template` to apply context-aware escaping:

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
	
	tmpl, err := template.New("ticket").Parse(`<html><body>
<h2>Ticket {{.TicketID}}</h2>
<p>Customer note: {{.CustomerNote}}</p>
</body></html>`)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
	
	data := struct {
		TicketID     string
		CustomerNote string
	}{
		TicketID:     ticketID,
		CustomerNote: customerNote,
	}
	
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "Execution error", http.StatusInternalServerError)
	}
}

func main() {
	http.HandleFunc("/support/ticket", ticketStatusHandler)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

The original code uses `fmt.Fprintf` to write HTML directly to the response with string interpolation. This bypasses any escaping mechanism, allowing an attacker to inject `<script>`, event handlers, or attribute breakouts via the `note` query parameter.

The fix uses Go's `html/template` package, which performs context-aware HTML entity encoding on all template variables by default. When `{{.CustomerNote}}` is rendered, any special characters (`<`, `>`, `&`, `"`, `'`) are automatically escaped to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), rendering injected scripts as plain text. The template is parsed once and executed with the untrusted data bound as struct fields, ensuring the escaping applies uniformly.

This closes CWE-79 by moving from unsafe string concatenation to a template engine that enforces output encoding at the language level.

## Behaviour changes

1. **Template parsing** — The code now parses the template string on each request. For production use, parse templates once at startup and reuse them to avoid repeated parsing overhead. This is a performance consideration, not a security regression.

2. **Error handling** — Template parsing and execution errors are now caught and return HTTP 500 responses. The original code would panic on invalid template syntax (if it occurred). The fix is more resilient but requires proper error logging at the application level to diagnose issues.

3. **Response buffering** — `tmpl.Execute()` writes directly to the response writer like `fmt.Fprintf`, so no buffering behaviour changes. Both produce the same streaming output.

4. **Character encoding** — Both versions set `Content-Type: text/html; charset=utf-8` identically, so character encoding is unchanged.

No behaviour changes that affect the application's functional contract. The fix preserves the original output format and HTTP semantics while adding the required escaping.

