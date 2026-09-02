## Verdict

Confirmed. `CommentView.Render` in `comment_view.go` builds an HTML response with `fmt.Sprintf` and writes attacker-controlled fields directly into the markup without any HTML-context encoding. Neither collaborator upstream of it performs escaping either, so the vulnerability is real and unmitigated along the whole chain.

## Source

`SubmitFeedbackHandler` in `feedback_handler.go` reads two untrusted form fields straight from the HTTP request:

- `req.Author = r.FormValue("author")`
- `req.Message = r.FormValue("message")`

These are attacker-controlled: any visitor submitting the support widget's feedback form chooses their own values. They flow into `FeedbackService.HandleSubmission`, which copies them into a `Comment{Author, Message}` unmodified, then passes that `Comment` to `CommentFormatter.PrepareForDisplay`. The formatter only trims whitespace and truncates length (`c.Author`, and `Message` via `summarize()` into `c.Excerpt`) - it explicitly does not encode for HTML, as its own doc comment states. The still-raw `Author` and `Excerpt` reach `CommentView.Render`, where they are interpolated into an HTML string with `fmt.Sprintf` and written to the `http.ResponseWriter` with `v.w.Write([]byte(html))` - the sink at line 24 of `comment_view.go`. An author value such as `<img src=x onerror=alert(document.cookie)>` or a message containing `</p><script>...</script>` is emitted verbatim into the page served to every visitor who triggers the render, giving stored/reflected XSS in the victim's browser session.

## Fix

Replace the manual `fmt.Sprintf` HTML assembly in `comment_view.go` with Go's context-aware autoescaping template engine, `html/template`, so `Author` and `Excerpt` are escaped for the HTML context they are placed in:

```go
package feedback

import (
	"html/template"
	"net/http"
)

var commentTmpl = template.Must(template.New("comment").Parse(
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
	return commentTmpl.Execute(v.w, c)
}
```

`html/template` (as opposed to `text/template`) tracks the HTML/JS/CSS/URL context each `{{.Field}}` sits in and applies the matching escaper automatically, so `<`, `>`, `&`, `"`, and `'` in `c.Author` and `c.Excerpt` are neutralized before they reach the response body - closing the sink without needing any change to `feedback_handler.go`, `feedback_service.go`, or `comment_formatter.go`.

## Explanation

The root cause is that HTML generation was done with string concatenation/formatting (`fmt.Sprintf`) instead of a templating mechanism that understands HTML syntax. `fmt.Sprintf` has no notion of HTML special characters, so any `<`, `>`, `"`, or `&` in `c.Author` or `c.Excerpt` is emitted as literal markup, letting an attacker close the surrounding tag and inject a new element (e.g., `<script>`, `<img onerror=...>`, or an attribute-breaking payload).

Fixing at the render step, rather than trying to sanitize in `CommentFormatter` or reject bad input in the handler, is deliberate: `CommentFormatter`'s job is display shaping (trim/truncate), not security encoding, and encoding is context-dependent - the same `Author` string could later be reused in a different context (an email, a log line, a JSON API) where HTML-escaping would be wrong. Centralizing the escaping at the one place that actually emits HTML, via `html/template`, keeps the encoding correct for its output context and prevents any future call site from forgetting to escape, since the template engine escapes by default rather than requiring every caller to remember to do so manually. The `Content-Type: text/html; charset=utf-8` header is preserved so the browser interprets the encoded output in a fixed, unambiguous charset, which also closes off charset-confusion-based encoding bypasses.
