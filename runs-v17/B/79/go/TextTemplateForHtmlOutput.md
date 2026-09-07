## Verdict

The finding is **confirmed**. The code uses `text/template` to render untrusted query parameter data directly into HTML output without encoding. `text/template` does not perform automatic HTML escaping, allowing an attacker to inject arbitrary HTML and JavaScript.

## Source

Line 18: `subject := r.URL.Query().Get("subject")` - untrusted query parameter

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

The fix replaces `text/template` with `html/template`. The `html/template` package provides the same API as `text/template` but automatically performs context-aware HTML escaping when rendering values into templates. When `{{.Subject}}` is executed, the value is HTML-encoded (e.g., `<` becomes `&lt;`, `>` becomes `&gt;`, `"` becomes `&#34;`), which prevents XSS injection.

An attacker attempting to inject `<script>alert('XSS')</script>` will now see it safely rendered as literal text in the HTML, rather than as executable code.

## Behaviour changes

- Query parameter values containing HTML special characters (e.g., `<`, `>`, `"`, `&`) are now displayed as literal text rather than being interpreted as HTML markup.
- Legitimate input containing these characters continues to display correctly.
- No changes to the HTTP handler's signature or its routing behavior.
- The Content-Type header remains `text/html` and is correctly set before template execution.

**Verification performed**: The fixed code compiles without errors (`go build` successful) and passes `go vet` checks.
