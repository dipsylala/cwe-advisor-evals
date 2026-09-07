## Verdict

Exploitable. The `subject` query parameter (line 18) flows directly into template rendering (line 28) via `text/template`, which performs no HTML escaping. An attacker can inject script tags or event handlers: `?subject=<script>alert('xss')</script>` executes in the victim's browser.

## Source

Line 18: `subject := r.URL.Query().Get("subject")` — untrusted user input from URL query parameter.

## Sink

Line 28: `ticketPage.Execute(w, data)` — the sink uses `text/template` (imported line 5), which does not escape HTML. The template binds `{{.Subject}}` in HTML body context (line 12) without escaping.

## Fix

**Vulnerable code:**
```go
import (
	"net/http"
	"text/template"
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
```

**Fixed code:**
```go
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
```

## Explanation

Replace `text/template` with `html/template` in the import statement. The `html/template` package performs context-aware HTML escaping automatically on all template data bindings. When `subject` contains `<`, `>`, `&`, or quotes, `html/template` encodes them as HTML entities (`&lt;`, `&gt;`, `&amp;`, `&#34;`) so they render as visible text rather than executable code. This eliminates the XSS vulnerability while preserving legitimate content. The template and data structure remain unchanged; only the package import changes, so the template execution contract is identical.

## Behaviour changes

None. The `html/template.Execute` call has the same signature and contract as `text/template.Execute`. Both parse templates at import time and render them to the response writer at runtime. The only difference is that `html/template` escapes template data automatically while `text/template` does not. Legitimate content containing `<`, `&`, and quotes continues to render correctly, now as escaped text. An attacker payload like `<script>alert('xss')</script>` now renders as visible text (`&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;`) instead of executing.
