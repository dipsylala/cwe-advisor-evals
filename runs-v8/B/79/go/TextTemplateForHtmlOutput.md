## Verdict

CWE-79 is confirmed. The code uses `text/template`, which provides no HTML escaping. Untrusted user input (`subject` query parameter) flows directly into the template output without context-aware encoding, allowing arbitrary script injection.

## Source

Line 18: `subject := r.URL.Query().Get("subject")` - untrusted query parameter.

Data flows into the template struct (lines 20-24) and is rendered at line 28 via `ticketPage.Execute(w, data)`.

## Fix

Replace `text/template` with `html/template`. This enables automatic context-aware HTML escaping.

**Change line 5:**
```go
// FROM:
import (
    "net/http"
    "text/template"
)

// TO:
import (
    "net/http"
    "html/template"
)
```

**Change line 8:**
```go
// FROM:
var ticketPage = template.Must(template.New("ticket").Parse(`

// TO:
var ticketPage = template.Must(html.New("ticket").Parse(`
```

Alternatively, use fully qualified names:
```go
var ticketPage = html.Must(html.New("ticket").Parse(`
```

Or keep the import simple and use:
```go
var ticketPage = template.Must(template.New("ticket").Parse(`
```

after changing the import to `html/template`. The `template` alias then refers to `html/template`.

## Explanation

`text/template` is a generic templating engine with no security escaping. `html/template` is a specialization that provides context-aware HTML escaping: HTML body text is escaped (`<` becomes `&lt;`), attribute values are escaped, and JavaScript and URL contexts are handled correctly. By switching the import and template package, the `{{.Subject}}` placeholder will automatically escape any injected HTML/JavaScript, rendering it harmless as literal text.

This is the primary Go defence for XSS and requires no additional code changes. The template parsing, data binding, and execution flow remain identical; only the escaping behaviour changes.

## Behaviour changes

Legitimate content containing `<`, `>`, `&`, and quotes will now display as-is in the rendered page (escaped in HTML) instead of being interpreted as markup. For example:

- User input `subject=5 < 10` will render as `5 &lt; 10` in the page (visible as `5 < 10` to the browser).
- User input `subject=<script>alert('xss')</script>` will render as `&lt;script&gt;alert('xss')&lt;/script&gt;` (visible as escaped text, not executed).

This is the intended and correct behaviour. If the application requires rendering user-supplied rich HTML (unlikely for a ticket subject), that would require a separate allowlist sanitization step using `github.com/microcosm-cc/bluemonday`.
