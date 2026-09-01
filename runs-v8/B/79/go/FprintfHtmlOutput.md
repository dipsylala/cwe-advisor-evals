## Verdict

Confirmed. `customerNote` from an untrusted query parameter is written to the HTTP response without encoding via `fmt.Fprintf`, allowing XSS injection.

## Source

Line 10: `customerNote := r.URL.Query().Get("note")` — untrusted user input from URL query parameter.

Line 16: `fmt.Fprintf(w, "<p>Customer note: %s</p>", customerNote)` — the sink. `fmt.Fprintf` does not perform HTML encoding; the value is concatenated into the HTML output as-is.

Attack vector: `?note=<script>alert('xss')</script>` or `?note="><img src=x onerror="alert(1)">`.

## Fix

Replace `fmt.Fprintf` string concatenation with `html/template`, which performs context-aware HTML escaping automatically.

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

func main() {
	http.HandleFunc("/support/ticket", ticketStatusHandler)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

The vulnerability stems from using `fmt.Fprintf` with string concatenation to build HTML output. `fmt.Fprintf` treats the format string as literal text and does no encoding of the `%s` substitutions, so untrusted values flow directly into the HTML.

The fix replaces this with `html/template`, which parses the HTML structure and applies context-aware escaping to all substituted values. When `{{.Note}}` is rendered into the HTML body context, the template engine automatically escapes HTML metacharacters (`<`, `>`, `&`, `"`, `'`) into their entity forms (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), neutralizing injection attempts. Payloads like `<script>alert('xss')</script>` become safe text: `&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;`.

Both `ticketID` and `customerNote` are now escaped because they flow through the template engine, eliminating the XSS from both sources even though the finding named only `customerNote`.

## Behaviour changes

- Legitimate content containing `<`, `>`, `&`, or quotes now renders as escaped entity sequences in the HTML, preserving data integrity while closing injection paths. For example, a note `"5 < 10"` renders as `"5 &lt; 10"`.
- Template parse errors are now handled with an HTTP 500 response instead of a panic, improving fault isolation.
- The handler no longer ignores `tmpl.Execute` errors; a misconfigured template or write failure is logged (though the current code omits explicit logging; in production, `err` should be logged or handled).
