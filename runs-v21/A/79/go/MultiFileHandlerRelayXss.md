## Verdict
CONFIRMED

## Source
The vulnerability originates from untrusted form input supplied by `r.FormValue("author")` and `r.FormValue("message")` in `feedback_handler.go` line 19-20. This data flows through `FeedbackService.HandleSubmission()` and `CommentFormatter.PrepareForDisplay()` (which explicitly do not escape for HTML), and reaches `CommentView.Render()` where it is directly interpolated into an HTML response.

## Fix

### File: comment_view.go
```go
package feedback

import (
	"fmt"
	"html"
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
	html := fmt.Sprintf("<div class=\"comment\"><h3>%s says:</h3><p>%s</p></div>", html.EscapeString(c.Author), html.EscapeString(c.Excerpt))
	// SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
	_, err := v.w.Write([]byte(html))
	return err
}
```

## Explanation
The XSS vulnerability occurs because user-controlled data (`c.Author` and `c.Excerpt`) is directly embedded into HTML without escaping. An attacker could inject script tags or event handlers through the feedback form.

The fix applies `html.EscapeString()` to both untrusted fields before they are interpolated into the HTML template. This function converts special HTML characters (`<`, `>`, `&`, `"`, `'`) into their corresponding HTML entities, preventing script injection while preserving the intended display content.

Go's `html.EscapeString()` is the standard library's primary HTML escaping function and is suitable for this context where content is being rendered directly into HTML.
