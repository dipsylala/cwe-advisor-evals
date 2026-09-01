## Verdict

The vulnerability is real. User-controlled data from `FeedbackRequest` flows through `FeedbackService` and `CommentFormatter` to `CommentView.Render()`, where it is interpolated directly into an HTML string without escaping and written to the HTTP response.

## Source

The source is the HTTP form input captured in `feedback_handler.go`:
- Line 19: `Author:  r.FormValue("author")`
- Line 20: `Message: r.FormValue("message")`

This untrusted input flows through `FeedbackService.HandleSubmission()` → `CommentFormatter.PrepareForDisplay()` to `CommentView.Render()`, where `c.Author` and `c.Excerpt` remain unescaped.

## Fix

In `comment_view.go`, import the `html` package and escape both `c.Author` and `c.Excerpt` before interpolating them into the HTML template:

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
	_, err := v.w.Write([]byte(html))
	return err
}
```

## Explanation

The fix applies HTML entity encoding to both `c.Author` and `c.Excerpt` using `html.EscapeString()` from Go's standard library. This function converts special HTML characters (`<`, `>`, `&`, `"`, `'`) into their respective HTML entities (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), rendering any injected script tags or event handlers as literal text rather than executable code.

The encoding happens at the point where untrusted data is inserted into HTML markup—the natural location where context switching occurs from program data to HTML syntax. This satisfies the primary defence: untrusted input is escaped before being placed into HTML content context.
