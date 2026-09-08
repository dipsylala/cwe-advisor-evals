## Verdict

The vulnerability is confirmed. Untrusted HTTP form input (`Author` and `Excerpt` fields) reaches the HTML output sink without encoding, allowing script injection.

## Source

**feedback_handler.go, lines 19-20**: HTTP form parameters `r.FormValue("author")` and `r.FormValue("message")` are untrusted sources controlled by the attacker.

The data flows through:
1. FeedbackRequest struct (feedback_handler.go)
2. FeedbackService.HandleSubmission → formatter.PrepareForDisplay (feedback_service.go)
3. CommentFormatter.PrepareForDisplay normalizes but does not encode (comment_formatter.go)
4. CommentView.Render builds and writes HTML (comment_view.go)

## Fix

### File: comment_view.go

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
	
	tmpl, err := template.New("comment").Parse(`<div class="comment"><h3>{{.Author}} says:</h3><p>{{.Excerpt}}</p></div>`)
	if err != nil {
		return err
	}
	
	return tmpl.Execute(v.w, c)
}
```

## Explanation

The original code at line 22 used `fmt.Sprintf` to build an HTML string, directly concatenating untrusted `c.Author` and `c.Excerpt` values into the HTML without any encoding. Line 24 then wrote this unencoded string to the response.

The fix replaces `fmt` (string concatenation) with Go's `html/template` package, which provides context-aware escaping. The template syntax `{{.Author}}` and `{{.Excerpt}}` are automatically escaped for safe HTML body context: special characters like `<`, `>`, `&`, `"`, and `'` are converted to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`). This prevents an attacker-controlled payload like `"><script>alert('xss')</script><h3 class="` from being interpreted as executable code.

The `template.Execute()` method writes directly to the response writer, maintaining the same control flow and error handling semantics as the original code.

## Behaviour changes

1. **Import change**: Replaced `"fmt"` with `"html/template"`.
2. **Rendering approach**: Changed from string concatenation via `fmt.Sprintf` to template parsing and execution.
3. **HTML output**: Untrusted input fields are now HTML-escaped (e.g., `<` becomes `&lt;`), which renders correctly in browsers but prevents script injection.

No functional change to legitimate comment display. Comments containing special characters will render with HTML entities visible, which is the secure and correct behavior for data that should not be interpreted as markup.

