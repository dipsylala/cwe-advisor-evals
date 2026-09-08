## Verdict

Confirmed. `CommentView.Render` in `comment_view.go` builds the HTML fragment with `fmt.Sprintf`, writing `c.Author` and `c.Excerpt` directly into the markup. Both fields trace back to unauthenticated form input (`author` and `message` on `SubmitFeedbackHandler`) and pass through `CommentFormatter.PrepareForDisplay`, which only trims whitespace and truncates length - it does not perform any HTML encoding. A message or author name containing `<script>` or an event-handler attribute is written verbatim into the response and executes in the visitor's browser (reflected/stored XSS depending on how the feedback is later displayed).

## Source

`r.FormValue("author")` and `r.FormValue("message")` in `SubmitFeedbackHandler` (`feedback_handler.go`), flowing unchanged through `FeedbackRequest` -> `Comment` -> `CommentFormatter.PrepareForDisplay` (`comment_formatter.go`, trims/truncates only) -> `CommentView.Render` (`comment_view.go`), where the sink `v.w.Write([]byte(html))` writes the unescaped `fmt.Sprintf` result to the response body.

## Fix

### File: comment_view.go
```go
package feedback

import (
	"bytes"
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

var commentTemplate = template.Must(template.New("comment").Parse(
	`<div class="comment"><h3>{{.Author}} says:</h3><p>{{.Excerpt}}</p></div>`,
))

// Render writes the comment's author and excerpt into an HTML snippet that
// is appended below the feedback form on the support page.
func (v *CommentView) Render(c Comment) error {
	v.w.Header().Set("Content-Type", "text/html; charset=utf-8")

	var buf bytes.Buffer
	if err := commentTemplate.Execute(&buf, c); err != nil {
		return err
	}

	_, err := v.w.Write(buf.Bytes())
	return err
}
```

## Explanation

`html/template` (unlike `text/template`) tracks the HTML context of each `{{...}}` action and automatically applies the correct contextual escaping - here, HTML-entity escaping for text inside `<h3>` and `<p>` elements - so any `<`, `>`, `&`, `"`, or `'` in `c.Author` or `c.Excerpt` is neutralized into inert text instead of being parsed as markup. This is a drop-in replacement for `fmt.Sprintf`: `Comment`'s exported `Author` and `Excerpt` fields are used directly as the template's data, the same HTTP response and content type are preserved, and no upstream file needs to change. Fixing at the render step (the sink) rather than in `CommentFormatter` also keeps the escaping applied exactly once, at the point where the value actually becomes HTML, regardless of how many other callers might reuse the formatter's trimmed/truncated `Comment` for a non-HTML destination (e.g. a log line or JSON API) where escaping would be wrong.

A quick verification: feeding `Author = "<script>alert(1)</script>"` through the fixed `Render` produces `&lt;script&gt;alert(1)&lt;/script&gt;` in the output instead of a live `<script>` tag, whereas the original `fmt.Sprintf` version emits it unescaped and the browser executes it.
