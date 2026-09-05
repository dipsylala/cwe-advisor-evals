## Verdict

Exploitable. Untrusted user input from `r.URL.Query().Get("note")` flows directly to an HTML output sink without encoding, allowing attackers to inject arbitrary HTML and JavaScript into the HTTP response.

## Source

The untrusted data sources are query parameters obtained via `r.URL.Query().Get()`:
- Line 9: `ticketID := r.URL.Query().Get("id")` - URL query parameter
- Line 10: `customerNote := r.URL.Query().Get("note")` - URL query parameter

These values are under attacker control and are never validated, constrained, or encoded before output.

## Fix

**Vulnerable code (lines 8-18):**
```go
func ticketStatusHandler(w http.ResponseWriter, r *http.Request) {
	ticketID := r.URL.Query().Get("id")
	customerNote := r.URL.Query().Get("note")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body>")
	fmt.Fprintf(w, "<h2>Ticket %s</h2>", ticketID)
	// SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
	fmt.Fprintf(w, "<p>Customer note: %s</p>", customerNote)
	fmt.Fprintf(w, "</body></html>")
}
```

**Fixed code:**
```go
func ticketStatusHandler(w http.ResponseWriter, r *http.Request) {
	ticketID := r.URL.Query().Get("id")
	customerNote := r.URL.Query().Get("note")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	
	tmpl, err := template.New("ticket").Parse(`<html><body>
<h2>Ticket {{.ID}}</h2>
<p>Customer note: {{.Note}}</p>
</body></html>`)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
	
	data := struct {
		ID   string
		Note string
	}{
		ID:   ticketID,
		Note: customerNote,
	}
	
	tmpl.Execute(w, data)
}
```

Update imports at the top of the file:
```go
import (
	"html/template"
	"net/http"
)
```

(Remove `"fmt"` as it is no longer used.)

## Explanation

The original code uses `fmt.Fprintf` with string concatenation to build HTML dynamically, which provides no protection against XSS. Query parameters are inserted directly into the HTML output without any encoding. An attacker can inject a URL like `/support/ticket?note=<script>alert('XSS')</script>` to execute arbitrary JavaScript in the victim's browser.

The fix replaces the unsafe string-concatenation pattern with `html/template`, which provides context-aware automatic output encoding. Template variables like `{{.Note}}` are automatically HTML-escaped by the template engine, converting dangerous characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`). This ensures that user-supplied data remains data and cannot be interpreted as HTML markup or executable script code. The template approach is the primary defence recommended by the Go standard library and CWE-79 guidance for this language.

## Behaviour changes

1. **Error handling added:** A new error case checks whether the template parsing fails. If parsing fails (which would only happen with a malformed template string), the handler returns an HTTP 500 error instead of attempting to execute a nil template. This is a necessary addition because `template.New().Parse()` can error, whereas the original code had no error path.

2. **Response type consistency:** The original code called `fmt.Fprintf()` multiple times, each appending to the response. The fixed code uses a single `template.Execute()` call to write the entire response in one operation. This ensures consistent context-aware escaping across all template variables and is the pattern required by the Go template safety model.

3. **Data structure required:** The fix introduces a temporary struct to hold template variables. This is required by Go's template system to bind values to template placeholders, and has no security or functional downside - it binds the same values that were previously passed inline.

No changes to the public API contract, HTTP response headers (other than content already specified), or business logic beyond closing the injection vector.
