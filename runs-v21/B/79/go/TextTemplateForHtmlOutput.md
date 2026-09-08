## Verdict

The vulnerability is confirmed and remediable. The code uses `text/template` to render untrusted user input (the `subject` query parameter) directly into an HTML document without any output encoding, allowing XSS injection.

## Source

- **Input origin**: `r.URL.Query().Get("subject")` at line 18
- **Flow**: Query parameter → `data.Subject` struct field → template variable `{{.Subject}}` at line 12 → `Execute` output at line 28
- **Sink**: `text/template.Execute(w, data)` at line 28
- **Exploitability**: Attacker can set `?subject=<script>alert('XSS')</script>` and the script executes in the browser

## Fix

Replace the import at line 5 to use `html/template` instead of `text/template`.

### File: TextTemplateForHtmlOutput.go

```go
package main

import (
	"html/template"
	"net/http"
)

var ticketPage = template.Must(template.New("ticket").Parse(`
	<html>
		<body>
			<h2>Ticket Status</h2>
			<p>Subject: {{.Subject}}</p>
		</body>
	</html>
`))

func ticketStatusHandler(w http.ResponseWriter, r *http.Request) {
	subject := r.URL.Query().Get("subject")

	data := struct {
		Subject string
	}{
		Subject: subject,
	}

	w.Header().Set("Content-Type", "text/html")
	ticketPage.Execute(w, data)
}

func main() {
	http.HandleFunc("/ticket/status", ticketStatusHandler)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

The Go standard library provides two template packages: `text/template` and `html/template`. The key difference is that `html/template` performs context-aware output encoding automatically, while `text/template` does not. Since this code outputs to an HTTP response with `Content-Type: text/html`, it must use `html/template`.

By switching to `html/template`, the template engine automatically escapes the `{{.Subject}}` value for HTML body context, converting dangerous characters like `<`, `>`, `&`, and quotes into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&#34;`, etc.). This prevents injected script tags and event handlers from being interpreted as code by the browser. The template syntax and the Execute method call remain unchanged, so the fix is purely a package swap.

Verification: Go compiler `go vet` accepts the fixed code without errors. The `html/template` package is part of Go's standard library and has an API-compatible interface with `text/template`.

## Behaviour changes

No functional behaviour changes:
- The HTTP response structure and headers remain identical
- Template syntax is unchanged
- The `Execute` method signature and return type are unchanged
- The output to the HTTP response writer continues to work as before
- Legitimate content containing `<`, `&`, `"`, and `'` characters is properly escaped and displays correctly (e.g., `subject=A & B` renders as `A &amp; B`)

Security impact: Injection payloads like `<script>alert(1)</script>` are converted to literal text (`&lt;script&gt;alert(1)&lt;/script&gt;`) and no longer execute in the browser.
