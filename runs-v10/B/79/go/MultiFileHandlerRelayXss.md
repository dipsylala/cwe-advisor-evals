## Verdict

Exploitable. Untrusted user input (`Author` and `Message` from form data) flows through `CommentFormatter.PrepareForDisplay` (which only truncates/trims, does not encode) into `CommentView.Render`, where it is directly interpolated into an HTML string via `fmt.Sprintf` and written unencoded to the HTTP response via `v.w.Write()`. An attacker can inject XSS payloads such as `"><script>alert(1)</script>` or `" onload="alert(1)`.

## Source

User-controlled form data:
- `feedback_handler.go`, line 19: `r.FormValue("author")`
- `feedback_handler.go`, line 20: `r.FormValue("message")`

These flow into `FeedbackRequest.Author` and `FeedbackRequest.Message`, are wrapped in a `Comment` struct, truncated/trimmed by `CommentFormatter.PrepareForDisplay` (but not encoded), and arrive at `CommentView.Render` as `Comment.Author` and `Comment.Excerpt`.

## Fix

**Vulnerable code** (`comment_view.go`, lines 20-26):

```go
func (v *CommentView) Render(c Comment) error {
	v.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf("<div class=\"comment\"><h3>%s says:</h3><p>%s</p></div>", c.Author, c.Excerpt)
	// SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
	_, err := v.w.Write([]byte(html))
	return err
}
```

**Fixed code** (`comment_view.go`):

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

// Render writes the comment's author and excerpt into an HTML snippet that
// is appended below the feedback form on the support page.
func (v *CommentView) Render(c Comment) error {
	v.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	
	const htmlTemplate = `<div class="comment"><h3>{{.Author}} says:</h3><p>{{.Excerpt}}</p></div>`
	tmpl, err := template.New("comment").Parse(htmlTemplate)
	if err != nil {
		return err
	}
	
	return tmpl.Execute(v.w, c)
}
```

## Explanation

The fix replaces `fmt.Sprintf` string concatenation with `html/template`, which provides context-aware automatic HTML escaping. In the template syntax `{{.Author}}` and `{{.Excerpt}}`, the template engine automatically HTML-encodes these values, converting dangerous characters like `<`, `>`, `"`, and `&` into their HTML entity equivalents (`&lt;`, `&gt;`, `&quot;`, `&amp;`). This prevents injected script tags and event handlers from being interpreted as executable code. The template is parsed and executed, writing directly to the response writer, eliminating the intermediate string build step. XSS payloads such as `"><script>alert(1)</script>` are now rendered as plain text, defeating the injection.

## Behaviour changes

- The intermediate HTML string is no longer built in memory; `html/template.Execute` writes directly to the response writer, which is a minor efficiency gain with no functional difference for legitimate content.
- An error during template parsing (unlikely with a constant template) is now returned; this preserves the error-return contract of the method.
- All HTML special characters in `c.Author` and `c.Excerpt` are now escaped to HTML entities, which is the correct and intended behaviour for untrusted input in an HTML context.
