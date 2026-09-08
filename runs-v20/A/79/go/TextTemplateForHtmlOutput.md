## Verdict

Confirmed. `ticketPage` is built with `text/template`, which performs no output encoding at all. The `subject` query parameter flows unmodified from `r.URL.Query().Get("subject")` into `data.Subject`, and `ticketPage.Execute(w, data)` writes it straight into an HTML response whose `Content-Type` is `text/html`. A request such as `/ticket/status?subject=<script>alert(1)</script>` is reflected verbatim into the page and executes in the victim's browser - classic reflected XSS.

## Source

`r.URL.Query().Get("subject")` on line 18, in `ticketStatusHandler`.

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

The only change is the import: `text/template` becomes `html/template`. Both packages expose an identical `Parse`/`Execute` API, which is why the rest of the file is untouched, but `html/template` parses the template and tracks the HTML/JS/CSS/URL context each `{{.Field}}` action falls in, then applies the matching contextual escaping automatically at execution time. Here `{{.Subject}}` sits in an HTML text node, so `html/template` HTML-entity-encodes it (`<` becomes `&lt;`, `>` becomes `&gt;`, `"` becomes `&#34;`, etc.) before writing it out, which neutralizes `<script>` and any other markup or attribute-breakout attempt in the `subject` value while leaving ordinary subjects displayed unchanged. No other code needs to change: the fix works because `html/template` is a drop-in, escaping-aware superset of `text/template`'s API - there is no manual sanitization step to add, and adding one on top of `html/template` would only encode data twice.
