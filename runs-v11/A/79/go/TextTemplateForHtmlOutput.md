## Verdict
CWE-79 vulnerability confirmed. The code passes unescaped user input from `r.URL.Query().Get("subject")` into an HTML template rendered with `text/template`, allowing XSS attacks. A malicious `subject` parameter like `<script>alert('xss')</script>` executes in the browser.

## Source
- **Source**: `r.URL.Query().Get("subject")` (untrusted HTTP query parameter)
- **Sink**: `ticketPage.Execute(w, data)` at line 28
- **Data flow**: Query parameter → `Subject` struct field → template rendering → HTTP response body

## Fix
Replace `text/template` with `html/template`:

```go
import (
	"net/http"
	"html/template"  // Change from "text/template"
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
	ticketPage.Execute(w, data)  // Now safely escapes HTML
}
```

## Explanation
`html/template` automatically escapes values for the context where they appear. When `{{.Subject}}` is rendered in an HTML element context, the package escapes special characters: `<` becomes `&lt;`, `>` becomes `&gt;`, `&` becomes `&amp;`, and quotes are escaped appropriately. This prevents the injected script tag from being parsed as executable code—it renders as literal text in the HTML.

`text/template` performs no escaping and is unsafe for HTML output. `html/template` is a drop-in replacement with identical template syntax; only the import changes.
