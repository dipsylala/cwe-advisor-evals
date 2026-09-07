## Verdict

The vulnerability is **confirmed**. The code uses `text/template`, which does not auto-escape output for HTML contexts. Unsanitized user input from the `subject` query parameter flows directly into the template and is rendered into the HTTP response without HTML encoding, enabling XSS attacks.

## Source

Line 28 in TextTemplateForHtmlOutput.go: `ticketPage.Execute(w, data)`

The data flow is:
1. Line 18: `subject := r.URL.Query().Get("subject")` — user-controlled input from URL
2. Lines 20-24: Input wrapped in a struct field
3. Line 28: Template execution with unescaped output — the sink

## Fix

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

The fix changes the import on line 4 from `text/template` to `html/template`. The `html/template` package automatically escapes template output to be safe for HTML contexts. This means any special characters in the user-supplied `subject` value (such as `<`, `>`, `"`, `'`, `&`) will be HTML-encoded when rendered, preventing the browser from interpreting them as HTML or JavaScript.

For example, if the user provides `subject=<script>alert('XSS')</script>`, the `html/template` package will render it as `&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;`, which displays as plain text rather than executing code.

This is the idiomatic Go approach to preventing XSS in web applications: use `html/template` for HTML output, `text/template` for plain text, and the framework handles context-specific escaping automatically.
