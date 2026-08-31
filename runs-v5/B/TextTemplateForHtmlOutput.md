## Verdict

exploitable (CWE-79, Improper Neutralization of Input During Web Page Generation / Cross-Site Scripting)

- Location: `TextTemplateForHtmlOutput.go`, line 28 (`ticketPage.Execute(w, data)`)
- Confidence: high

## Source

`r.URL.Query().Get("subject")` (line 18) - the `subject` query parameter of the incoming HTTP request, fully attacker-controlled. It flows unmodified into the `Subject` field of an anonymous struct (lines 20-24), which is then passed as the data argument to `ticketPage.Execute`. No validation, encoding, or allowlist check occurs between source and sink.

## Fix

Vulnerable code:

```go
import (
	"net/http"
	"text/template"
)

var ticketPage = template.Must(template.New("ticket").Parse(`
	<html>
		<body>
			<h2>Ticket Status</h2>
			<p>Subject: {{.Subject}}</p>
		</body>
	</html>
`))
```

Fixed code:

```go
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
```

The template definition, `Execute` call, and handler logic (lines 8-28) are otherwise unchanged - only the import path for `template` moves from `text/template` to `html/template`.

## Explanation

The handler serves the executed template with `Content-Type: text/html`, but builds it with `text/template`, which performs no output escaping - it treats `{{.Subject}}` as plain text substitution with no awareness that the surrounding document is HTML. An attacker-controlled `subject` query parameter such as `<script>...</script>` or `"><svg onload=...>` is therefore emitted verbatim into the response body and executes in the victim's browser. `html/template` is API-compatible with `text/template` (`New`, `Parse`, `Must`, `Execute` all have identical signatures) but performs context-aware auto-escaping, so `{{.Subject}}` is HTML-entity-encoded before insertion, neutralizing markup and script content while preserving the literal text. Swapping the import is the complete, minimal fix per the loaded Go-specific CWE-79 guidance, which states `text/template` must never render browser-facing HTML and that `html/template` is the primary remediation.

## Behaviour changes

None beyond closing the weakness. `html/template` exposes the same `New`/`Parse`/`Must`/`Execute` API used here, so the call signatures, the returned `*Template`, and `Execute`'s error/write behaviour to `w` are unchanged. The only observable difference is that a `Subject` value containing HTML metacharacters (`<`, `>`, `&`, `"`, `'`) is now rendered as its escaped entity form instead of being inserted raw - this is the intended effect of the fix, not an incidental regression. Legitimate subject text with no such characters renders identically to before.
