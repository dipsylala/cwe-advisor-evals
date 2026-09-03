## Verdict

CONFIRMED. The code uses `text/template` to render untrusted user input (`subject` URL query parameter) into an HTML response without escaping. This allows XSS injection: an attacker can supply `subject=<script>alert('xss')</script>` to execute arbitrary JavaScript in victims' browsers.

## Source

- **Entry point**: Line 18, `r.URL.Query().Get("subject")` - untrusted user-supplied query parameter
- **Data flow**: Subject is assigned to the `data.Subject` struct field (line 21-24) and passed to template execution
- **Sink**: Line 28, `ticketPage.Execute(w, data)` - renders the untrusted value into HTML response via `text/template`

The vulnerability exists because `text/template` provides no automatic HTML encoding; the value passes through unchanged.

## Fix

**Before** (line 5):
```go
import (
	"net/http"
	"text/template"
)
```

**After** (line 5):
```go
import (
	"net/http"
	"html/template"
)
```

Replace the import statement only. No other changes needed. All existing code remains valid because `html/template` is a superset of `text/template` with the addition of context-aware HTML escaping.

## Explanation

`text/template` does not escape HTML by default, so any untrusted data rendered via its template actions appears unmodified in the response. `html/template` performs automatic context-aware escaping: the `{{.Subject}}` action now escapes HTML special characters (`<`, `>`, `&`, `"`, `'`) to their entity forms (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`). This prevents the injected script tag from being interpreted as code and executed by the browser. The escaping is applied at the template sink based on the context where the value appears (here, HTML body text), eliminating the XSS vector.

## Behaviour changes

- HTML special characters in the `subject` query parameter are now escaped in the rendered HTML.
- Legitimate values containing `<`, `&`, or quotes render correctly as escaped text: `subject=1&2` displays as "1&amp;2", `subject=<tag>` displays as "&lt;tag&gt;".
- Malicious payloads like `subject=<script>alert('xss')</script>` are rendered as harmless text: "&lt;script&gt;alert('xss')&lt;/script&gt;".
- Template execution performance and error handling remain unchanged.
