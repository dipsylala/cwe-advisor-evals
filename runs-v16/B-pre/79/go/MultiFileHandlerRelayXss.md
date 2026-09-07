## Verdict

Confirmed real. Untrusted form input flows from `SubmitFeedbackHandler` through `FeedbackService` and `CommentFormatter` to `CommentView.Render`, where it is interpolated into an HTML string via `fmt.Sprintf` and written directly without escaping, allowing arbitrary HTML/JavaScript injection.

## Source

`SubmitFeedbackHandler` (feedback_handler.go, line 19-20):
- `r.FormValue("author")` - untrusted user input from the feedback form
- `r.FormValue("message")` - untrusted user input from the feedback form

Both values flow through `FeedbackRequest` to `FeedbackService.HandleSubmission`, which wraps them in a `Comment` struct.

## Fix

Replace `comment_view.go` to use `html/template` for context-aware automatic escaping instead of string concatenation:

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
	
	tmpl, err := template.New("comment").Parse(
		`<div class="comment"><h3>{{.Author}} says:</h3><p>{{.Excerpt}}</p></div>`,
	)
	if err != nil {
		return err
	}
	
	return tmpl.Execute(v.w, c)
}
```

## Explanation

The original code built HTML by concatenating untrusted `c.Author` and `c.Excerpt` directly into an HTML string using `fmt.Sprintf`, then wrote it to the response without any escaping. The `html/template` package provides automatic, context-aware output encoding that escapes HTML special characters (`<`, `>`, `&`, `"`, `'`) in the values, preventing them from being interpreted as HTML or JavaScript code.

The fixed code uses `template.Parse` to define an HTML template where `{{.Author}}` and `{{.Excerpt}}` are template actions. When `Execute` renders the template, `html/template` automatically escapes these values for the HTML body context. An attacker-controlled payload like `<script>alert('XSS')</script>` or `"><img src=x onerror=alert(1)>` is rendered as literal text rather than executable code.

## Behaviour changes

No functional changes to the output. The HTML structure remains identical. The only difference is that characters with special meaning in HTML (`<`, `>`, `&`, `"`, `'`) in the author name or excerpt are escaped (e.g., `<` becomes `&lt;`), which prevents injection while preserving legitimate text that happens to contain these characters.
