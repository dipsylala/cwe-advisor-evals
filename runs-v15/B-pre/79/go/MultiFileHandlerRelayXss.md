## Verdict

Exploitable. Untrusted user input (author and message fields from HTTP request) flows through the service and formatter layers without encoding, then is directly interpolated into an HTML template using `fmt.Sprintf` and written to the response without any HTML escaping. An attacker can inject arbitrary JavaScript by supplying payloads like `<script>alert('xss')</script>` in the author or message fields.

## Source

HTTP form input in `SubmitFeedbackHandler`:
- `r.FormValue("author")` - attacker-controlled author name
- `r.FormValue("message")` - attacker-controlled message body

These values flow unchanged through `FeedbackService.HandleSubmission` and `CommentFormatter.PrepareForDisplay` (which explicitly does not encode) into the `Comment` struct, then to `CommentView.Render`.

## Fix

**Vulnerable code** (comment_view.go, line 22-24):
```go
html := fmt.Sprintf("<div class=\"comment\"><h3>%s says:</h3><p>%s</p></div>", c.Author, c.Excerpt)
// SAST FINDING: CWE-79 reported here. Sink is the next statement.
_, err := v.w.Write([]byte(html))
```

**Fixed code**:
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
		`<div class="comment"><h3>{{.Author}} says:</h3><p>{{.Excerpt}}</p></div>`)
	if err != nil {
		return err
	}
	
	return tmpl.Execute(v.w, c)
}
```

## Explanation

The fix replaces the unsafe string concatenation approach with Go's `html/template` package, which provides automatic, context-aware HTML escaping. The `{{.Author}}` and `{{.Excerpt}}` template expressions automatically escape dangerous HTML characters (`<`, `>`, `&`, `"`, `'`) in their output, preventing the injected script tags from being interpreted as executable code. The template is parsed and executed directly to the response writer, maintaining the same output structure while ensuring all user-supplied values are safely encoded. This approach aligns with the Go security guidance that stipulates `html/template` must be used for any browser-facing HTML output, as it is the only standard library package that provides context-aware escaping.

## Behaviour changes

None. The HTML output produced is identical in structure and semantics to the original, with the only difference being that dangerous characters in the author and excerpt fields are now escaped as HTML entities (e.g., `<` becomes `&lt;`), which renders the same visually but prevents script injection. The function signature, return type, header setting, and overall control flow remain unchanged. The template parsing error is handled as a returned error, consistent with the original error handling pattern.
