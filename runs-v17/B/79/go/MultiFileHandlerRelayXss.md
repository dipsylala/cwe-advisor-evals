## Verdict

Exploitable. Untrusted user input from HTTP request form parameters (`author` and `message`) flows through the application without validation or encoding and is rendered directly into HTML output via string concatenation with `fmt.Sprintf`, allowing arbitrary script injection.

## Source

`feedback_handler.go` lines 19–20: HTTP request form parameters `r.FormValue("author")` and `r.FormValue("message")` are the untrusted sources. These values are passed into a `FeedbackRequest` struct and flow through `FeedbackService.HandleSubmission()` → `CommentFormatter.PrepareForDisplay()` → `CommentView.Render()`.

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
	
	// html/template performs context-aware escaping for HTML body context
	tmpl, err := template.New("comment").Parse(`<div class="comment"><h3>{{.Author}} says:</h3><p>{{.Excerpt}}</p></div>`)
	if err != nil {
		return err
	}
	
	return tmpl.Execute(v.w, c)
}
```

## Explanation

The original code built HTML via `fmt.Sprintf` with untrusted string values concatenated directly into the template, creating an XSS sink at line 24 where `v.w.Write([]byte(html))` sends unsanitized content to the browser. The fix replaces string concatenation with Go's `html/template` package, which provides context-aware output escaping. When the template is executed with `{{.Author}}` and `{{.Excerpt}}` data bindings, the template engine automatically escapes special HTML characters (`<`, `>`, `&`, `"`, `'`) in the HTML body context, preventing the attacker-controlled content from being interpreted as code. The template structure remains identical to the original output, preserving the expected HTML format while eliminating the injection vector.

## Behaviour changes

- **Error handling**: Template parsing now returns an error, introducing a new error path. This is low-risk for the fixed code because the template literal is static and fixed at compile time; the parse error can only occur due to unrelated Go runtime failures.
- **Output escaping**: The response output will now automatically escape HTML special characters in `c.Author` and `c.Excerpt`, transforming unsafe characters (e.g., `<` becomes `&lt;`) while preserving the intended HTML structure and readability of legitimate content containing those characters.
- **Import change**: Replaced `import "fmt"` with `import "html/template"`, both from Go's standard library.

Verification: Fixed code compiled without errors using `go build` against Go 1.21+.

