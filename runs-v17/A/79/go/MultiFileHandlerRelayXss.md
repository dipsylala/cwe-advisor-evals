## Verdict

CONFIRMED. The `CommentView.Render()` method at line 24 of `comment_view.go` writes untrusted user input directly into HTML output without escaping. The `c.Author` and `c.Excerpt` fields originate from HTTP form parameters and are interpolated directly into the HTML template using `fmt.Sprintf()`, allowing an attacker to inject arbitrary JavaScript.

## Source

Data flow:
1. `FeedbackHandler` receives raw form values via `r.FormValue("author")` and `r.FormValue("message")`
2. These untrusted values are wrapped in a `FeedbackRequest` struct and passed to `FeedbackService.HandleSubmission()`
3. `FeedbackService` creates a `Comment` struct with the raw values and passes it to `CommentFormatter.PrepareForDisplay()`
4. `CommentFormatter` explicitly documents that it does NOT encode for HTML: "Neither step encodes the text for HTML output - that is left to whatever renders the comment"
5. The prepared `Comment` is passed to `CommentView.Render()`
6. **Sink (line 24):** `CommentView.Render()` uses `fmt.Sprintf()` to embed `c.Author` and `c.Excerpt` directly into an HTML string without escaping, then writes it to the response

Vulnerable pattern:
```
html := fmt.Sprintf("<div class=\"comment\"><h3>%s says:</h3><p>%s</p></div>", c.Author, c.Excerpt)
v.w.Write([]byte(html))
```

An attacker can inject payloads like `<script>alert('XSS')</script>` through the form fields, which will be executed in the browser of any user viewing the rendered feedback.

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

The fix adds the `html` package import and wraps both user-supplied values with `html.EscapeString()` before embedding them in the HTML template. `html.EscapeString()` converts dangerous HTML metacharacters to their entity equivalents:
- `<` → `&lt;`
- `>` → `&gt;`
- `&` → `&amp;`
- `"` → `&#34;`
- `'` → `&#39;`

This ensures that any attempt to inject scripts, event handlers, or other HTML constructs in the `c.Author` or `c.Excerpt` fields will be safely rendered as text content rather than interpreted as markup or code. The escaping is applied at the presentation layer (the render sink), which is where this responsibility belongs according to the architectural pattern established by the formatter's documentation.
