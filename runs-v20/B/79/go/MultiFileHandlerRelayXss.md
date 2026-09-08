## Verdict

Exploitable. Confidence: high.

- CWE-79 (Improper Neutralization of Input During Web Page Generation / Cross-Site Scripting)
- Location: `comment_view.go`, `CommentView.Render`, the `v.w.Write([]byte(html))` call (line 24), fed by the `fmt.Sprintf` immediately above it.

## Source

`SubmitFeedbackHandler` (`feedback_handler.go`) reads two attacker-controlled form fields directly off the incoming request:

- `r.FormValue("author")`
- `r.FormValue("message")`

These are wrapped into a `FeedbackRequest` and handed to `FeedbackService.HandleSubmission` (`feedback_service.go`), which copies them into a `Comment{Author, Message}` with no encoding or validation. That `Comment` passes through `CommentFormatter.PrepareForDisplay` (`comment_formatter.go`), which only trims whitespace and truncates length (`Author` capped at 40 chars via plain slicing, `Message` summarized into `Excerpt` capped at 160 chars) - neither operation neutralizes HTML metacharacters. The still-tainted `Author` and `Excerpt` reach `CommentView.Render`, which builds an HTML fragment with `fmt.Sprintf("<div class=\"comment\"><h3>%s says:</h3><p>%s</p></div>", c.Author, c.Excerpt)` and writes the raw bytes to the `http.ResponseWriter` with `Content-Type: text/html`. Neither `%s` substitution is HTML-escaped, so a value such as `<script>...</script>` or `"><img src=x onerror=...>` in either the `author` or `message` form field is emitted verbatim into the response and executes in the victim's browser. Nothing in the chain breaks the taint before the sink.

## Fix

### File: comment_view.go
```go
package feedback

import (
	"html/template"
	"net/http"
)

// commentTemplate renders a prepared Comment into the HTML fragment shown
// below the feedback form. html/template context-aware-escapes Author and
// Excerpt for HTML body content, so untrusted values cannot break out into
// markup or script.
var commentTemplate = template.Must(template.New("comment").Parse(
	`<div class="comment"><h3>{{.Author}} says:</h3><p>{{.Excerpt}}</p></div>`,
))

// CommentView renders a prepared Comment into the HTML fragment returned by
// the support widget's feedback endpoint.
type CommentView struct {
	w http.ResponseWriter
}

func NewCommentView(w http.ResponseWriter) *CommentView {
	return &CommentView{w: w}
}

// Render writes the comment's author and excerpt into an HTML snippet that
// is appended below the feedback form on the support page.
func (v *CommentView) Render(c Comment) error {
	v.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return commentTemplate.Execute(v.w, c)
}
```

## Explanation

The vulnerable code built the HTML fragment with `fmt.Sprintf` and wrote the resulting bytes straight to the response, so `Author` and `Excerpt` landed in the HTML body with no encoding. The fix replaces that string-concatenation-plus-`Write` pattern with a parsed `html/template` template holding the identical markup, and lets `Execute` write directly to the `http.ResponseWriter`. `html/template` walks the parsed tree and applies context-aware escaping for every `{{.Field}}` action - both `Author` and `Excerpt` are in the HTML body context here - so `<`, `>`, `&`, `"` and `'` are turned into HTML entities before they reach the client, which prevents the injected markup from being parsed as an element or attribute. This is the primary and sufficient remediation for this sink: no additional input validation is needed for the XSS finding, since encoding is applied at the point of output regardless of what the upstream formatter does or fails to do to the value.

## Behaviour changes

- Output encoding: `Author` and `Excerpt` are now HTML-escaped in the response body. Legitimate content containing `<`, `&`, or `"` (e.g. an author name like `A&B` or a message containing a code snippet) now renders as the literal character via its HTML entity instead of being interpreted as markup - this is the intended effect of the fix, not a regression, and matches how the fragment always should have rendered.
- Return type/value: unchanged - `Render` still returns a single `error`. Previously that was the `error` from `w.Write` (with its `int` byte count discarded); now it is the `error` from `template.Execute`, which likewise reports a failure to write to the underlying `ResponseWriter`. No caller inspects the discarded byte count, so this is not an observable change.
- `Content-Type` header, method signatures (`NewCommentView`, `Render`), and the constructor/struct shape are all unchanged.
- No other file in the call chain (`feedback_handler.go`, `feedback_service.go`, `comment_formatter.go`) required a change; the fix is scoped to the sink.

## Verification

Ran `go build ./...` and `go vet ./...` against the fixed `comment_view.go` alongside untouched copies of `comment_formatter.go`, `feedback_handler.go`, and `feedback_service.go` in a scratch module (Go 1.25.5, `go.mod` targeting go 1.21). Both commands completed with no diagnostics, confirming the file compiles, `html/template` is a standard-library import (no new dependency), and the `Comment` struct's exported `Author`/`Excerpt` fields are usable as template data without further wiring.

## Assumptions

None - the CWE ID matched the description, the language was unambiguous (Go), and the SAST-identified sink location (`comment_view.go` line 24) matched the flow traced from the handler through the service and formatter with no branch requiring a choice between competing interpretations.
