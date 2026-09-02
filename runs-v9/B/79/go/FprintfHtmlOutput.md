## Verdict

- **cwe_id**: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting'))
- **location**: `FprintfHtmlOutput.go`, line 16
- **verdict**: exploitable
- **confidence**: high
- **assumptions**: none

## Source

`r.URL.Query().Get("note")` (line 10) - the `note` query parameter on `GET /support/ticket`, attacker-controlled and read directly from the request with no validation or sanitization.

## Fix

**Vulnerable code:**

```go
func ticketStatusHandler(w http.ResponseWriter, r *http.Request) {
	ticketID := r.URL.Query().Get("id")
	customerNote := r.URL.Query().Get("note")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body>")
	fmt.Fprintf(w, "<h2>Ticket %s</h2>", ticketID)
	// SAST FINDING: CWE-79 reported here. Sink is the next statement.
	fmt.Fprintf(w, "<p>Customer note: %s</p>", customerNote)
	fmt.Fprintf(w, "</body></html>")
}
```

**Fixed code:**

```go
package main

import (
	"html/template"
	"net/http"
)

var ticketTemplate = template.Must(template.New("ticket").Parse(
	"<html><body><h2>Ticket {{.TicketID}}</h2><p>Customer note: {{.CustomerNote}}</p></body></html>",
))

type ticketPage struct {
	TicketID     string
	CustomerNote string
}

func ticketStatusHandler(w http.ResponseWriter, r *http.Request) {
	ticketID := r.URL.Query().Get("id")
	customerNote := r.URL.Query().Get("note")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	ticketTemplate.Execute(w, ticketPage{TicketID: ticketID, CustomerNote: customerNote})
}

func main() {
	http.HandleFunc("/support/ticket", ticketStatusHandler)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

The handler built its entire HTML response with `fmt.Fprintf`, interpolating the `note` query parameter directly into the response body with no output encoding, so a value like `<script>...</script>` in `note` is written verbatim into the page and executes in the victim's browser. The fix moves the whole response into a single `html/template` template, which performs context-aware HTML escaping automatically: `CustomerNote` is substituted through `{{.CustomerNote}}`, so `<`, `>`, `&`, `"`, and `'` are rendered as HTML entities instead of markup, and the reported injection point at line 16 is closed. Per the Go-specific guidance, the response is kept inside one parsed template rather than mixing `fmt.Fprintf` writes with `template.Execute` for the same output, because a partial `text/html`-style write ahead of a template execution can put escaping out of sync with the surrounding markup.

## Behaviour changes

- `ticketID` (the `id` query parameter, previously written via the unescaped `fmt.Fprintf(w, "<h2>Ticket %s</h2>", ticketID)` on line 14) is now also HTML-escaped through the same template. This is not the reported line, but the guidance requires the whole response to render through one parsed template rather than partial `Fprintf` writes mixed with `template.Execute`, so the adjacent, identically-shaped injection point in the same handler is closed as a consequence of that requirement rather than left inconsistent with the fixed line.
- For benign input (no special HTML characters), the bytes written to the response are unchanged - same tags, same text, same order.
- `ticketTemplate.Execute`'s error return is discarded, matching the original code, which also discarded every `fmt.Fprintf` error return; no new error-handling behavior was introduced.
- `Content-Type: text/html; charset=utf-8` header and the `/support/ticket` route are unchanged.
