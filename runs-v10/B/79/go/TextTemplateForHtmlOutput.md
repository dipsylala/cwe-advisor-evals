## Verdict

Confirmed: Untrusted query parameter reflected into HTML output without escaping. An attacker can inject arbitrary HTML/JavaScript via the `subject` query parameter.

## Source

Line 18: `subject := r.URL.Query().Get("subject")` — untrusted user input from the query string is extracted directly and passed into the template data struct (lines 20-24).

Data flow: Query parameter → `data.Subject` → template variable `{{.Subject}}` (line 12) → HTTP response rendered by `ticketPage.Execute()` at line 28.

## Fix

Replace the `text/template` import with `html/template`:

**Vulnerable code (lines 4-5):**
```go
import (
	"net/http"
	"text/template"
)
```

**Fixed code:**
```go
import (
	"net/http"
	"html/template"
)
```

The template definition at line 8 requires no changes — it will now use `html/template.New()` instead of `text/template.New()`, and the parser stays the same:

```go
var ticketPage = template.Must(template.New("ticket").Parse(`
	<html>
		<body>
			<h2>Ticket Status</h2>
			<p>Subject: {{.Subject}}</p>
		</body>
	</html>
`))
```

The `Execute()` call at line 28 remains unchanged — it will now perform context-aware HTML escaping automatically.

## Explanation

The `text/template` package renders template output as plain text with no escaping, making it unsafe for HTML rendering. The `html/template` package (a strict superset of `text/template`) automatically escapes data based on its context in the template: `{{.Subject}}` in an HTML body context will escape `<` as `&lt;`, `>` as `&gt;`, `&` as `&amp;`, and quotes appropriately, preventing injection of HTML tags and JavaScript.

This fix closes the XSS vulnerability by ensuring untrusted input is always encoded before reaching the browser.

## Behaviour changes

HTML-unsafe characters in the query parameter (e.g., `<`, `>`, `"`, `'`, `&`) will now be rendered as HTML entities rather than as raw HTML. For example:
- Input: `?subject=Test<script>alert(1)</script>`
- Old output: `Subject: Test<script>alert(1)</script>` (script executes)
- New output: `Subject: Test&lt;script&gt;alert(1)&lt;/script&gt;` (rendered as text)

Legitimate subject text containing these characters (e.g., "Price < $10") will still render correctly as escaped text. No other behaviour changes.
