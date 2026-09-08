## Verdict

Confirmed. `customerNote` (and `ticketID`) come from `r.URL.Query()` — attacker-controlled request input — and are written into the response body via `fmt.Fprintf` with no HTML encoding, so a value like `<script>...</script>` in the `note` or `id` query parameter is reflected and executed as markup in the victim's browser (reflected XSS).

## Source

`r.URL.Query().Get("id")` and `r.URL.Query().Get("note")` in `ticketStatusHandler` (`FprintfHtmlOutput.go:9-10`), flowing unescaped into the `fmt.Fprintf(w, ...)` sinks at lines 14, 16, and reaching the client because the handler is registered at `http.HandleFunc("/support/ticket", ...)`.

## Fix

### File: FprintfHtmlOutput.go
```go
package main

import (
	"html/template"
	"net/http"
)

var ticketTmpl = template.Must(template.New("ticket").Parse(
	"<html><body><h2>Ticket {{.TicketID}}</h2><p>Customer note: {{.CustomerNote}}</p></body></html>"))

func ticketStatusHandler(w http.ResponseWriter, r *http.Request) {
	ticketID := r.URL.Query().Get("id")
	customerNote := r.URL.Query().Get("note")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := ticketTmpl.Execute(w, struct {
		TicketID     string
		CustomerNote string
	}{
		TicketID:     ticketID,
		CustomerNote: customerNote,
	})
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func main() {
	http.HandleFunc("/support/ticket", ticketStatusHandler)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

The root cause is building HTML by string-formatting untrusted values with `fmt.Fprintf` instead of using a context-aware templating engine. `fmt.Fprintf`/`%s` performs no output encoding at all, so any HTML-significant characters (`<`, `>`, `"`, `'`, `&`) in `ticketID` or `customerNote` pass straight into the response body and are parsed as markup by the browser.

The fix replaces `fmt.Fprintf`-based string concatenation with Go's `html/template` package, which is HTML-context-aware and autoescapes every value substituted through `{{.Field}}` according to where it appears in the markup (element text here). Both `TicketID` and `CustomerNote` are passed through the template's data struct rather than interpolated into the format string, so `html/template` escapes them (e.g. `<` becomes `&lt;`) before they reach the client, neutralizing any injected markup while preserving the literal text of legitimate values. `html/template`'s `Execute` returns an error if template parsing/execution fails, which is now checked and surfaced as a 500 instead of silently writing a partial response. This is a minimal, non-breaking change: the same two query parameters are rendered in the same visual positions, only the encoding mechanism changes.
