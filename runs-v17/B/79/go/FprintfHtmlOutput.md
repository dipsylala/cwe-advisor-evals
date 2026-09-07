## Verdict

Confirmed CWE-79 (Cross-site Scripting). Untrusted user input from the `note` query parameter is rendered directly into HTML output via `fmt.Fprintf` at line 16 without any escaping, allowing arbitrary JavaScript execution in the victim's browser.

## Source

Data flow:
1. **Source** (line 10): `customerNote := r.URL.Query().Get("note")` — untrusted user input from HTTP query parameter
2. **Sink** (line 16): `fmt.Fprintf(w, "<p>Customer note: %s</p>", customerNote)` — writes directly to HTTP response without encoding

Attack vector: An attacker can craft a malicious URL like `http://localhost:8080/support/ticket?note=<script>alert('XSS')</script>` to inject arbitrary JavaScript that executes in victims' browsers when they visit the page.

## Fix

### File: FprintfHtmlOutput.go

```go
package main

import (
	"html/template"
	"net/http"
)

func ticketStatusHandler(w http.ResponseWriter, r *http.Request) {
	ticketID := r.URL.Query().Get("id")
	customerNote := r.URL.Query().Get("note")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	
	tmpl, err := template.New("ticket").Parse(`<html><body>
<h2>Ticket {{.ID}}</h2>
<p>Customer note: {{.Note}}</p>
</body></html>`)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	
	data := struct {
		ID   string
		Note string
	}{
		ID:   ticketID,
		Note: customerNote,
	}
	
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func main() {
	http.HandleFunc("/support/ticket", ticketStatusHandler)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

The fix replaces unsafe string concatenation with `html/template`, which performs automatic context-aware escaping of all template variables. 

The key changes:
1. **Import change**: Replaced `"fmt"` with `"html/template"` — `html/template` (not `text/template`) performs automatic HTML escaping
2. **Template parsing**: User input is now bound to template variables (`{{.ID}}` and `{{.Note}}`) instead of being embedded via string formatting
3. **Data binding**: Query parameters are passed through a struct to the template engine, maintaining a clean separation between code and output
4. **Automatic escaping**: `html/template` automatically escapes all variable output for HTML body context, converting `<`, `>`, `&`, `"`, and `'` to their HTML entity equivalents, neutralizing XSS payloads
5. **Error handling**: Added error handling for both template parsing and execution failures

This approach follows the Go guidance: "Always render HTML with `html/template`, never `text/template`, for any output served to a browser... keep an entire response inside one parsed template so context-aware escaping applies consistently; do not mix `fmt.Fprintf` writes with `template.Execute` for the same output."

With this fix, a payload like `<script>alert('XSS')</script>` is rendered as `&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;` in the HTML, preventing script execution.

## Behaviour changes

1. **Output encoding**: HTML special characters in user input are now entity-encoded (e.g., `<` becomes `&lt;`), so they display as literal text in the browser rather than being interpreted as HTML markup
2. **Error handling**: Template parsing errors now return HTTP 500 status instead of crashing silently or writing partial HTML
3. **Performance**: Negligible impact; the overhead of parsing a small template once per request is minimal
4. **Content-Type header**: Remains unchanged (`text/html; charset=utf-8`), correctly set before output
5. **Functional behavior**: Legitimate content containing special characters (e.g., URLs with `&`, prices with `$`) is rendered correctly by the escaping, improving usability

Verification (checked with `go build` and `go vet`): Build successful, no warnings.
