## Verdict

Confirmed. The code is vulnerable to XSS via unsanitized user input.

## Source

The vulnerability occurs at line 28 where `ticketPage.Execute(w, data)` outputs user-supplied input to the HTTP response without HTML escaping. The `subject` parameter originates from untrusted user input via `r.URL.Query().Get("subject")` at line 18 and is injected directly into the HTML template via the `{{.Subject}}` placeholder at line 12.

Because the template is parsed using `text/template` (line 5, imported at line 4), there is no automatic HTML escaping. An attacker can supply a query string like `?subject=<script>alert('xss')</script>` to execute arbitrary JavaScript in the victim's browser.

## Fix

Replace `text/template` with `html/template`:

```go
package main

import (
	"net/http"
	"html/template"
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

The `html/template` package is identical to `text/template` except it automatically HTML-escapes all template data by default. When a template variable is rendered, special characters (`<`, `>`, `&`, `"`, `'`) are escaped to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), preventing injected HTML tags and scripts from being interpreted by the browser.

With this change, a payload like `<script>alert('xss')</script>` will be rendered as the literal string `&lt;script&gt;alert('xss')&lt;/script&gt;`, which displays as text rather than executing as code. This is the standard defense for template-based XSS in Go web applications handling untrusted input.

