## Verdict
XSS vulnerability confirmed. User-controlled input flows from form fields through to unescaped HTML output.

## Source
The vulnerability originates in `SubmitFeedbackHandler` (feedback_handler.go) where form values are extracted directly from the HTTP request: `r.FormValue("author")` and `r.FormValue("message")`. These untrusted values flow through `FeedbackService.HandleSubmission()` into `CommentFormatter.PrepareForDisplay()`, which normalizes but does not escape them. The prepared `Comment` is then passed to `CommentView.Render()` where at line 24, the `Author` and `Excerpt` fields are interpolated directly into an HTML string via `fmt.Sprintf()`, creating the XSS sink.

## Fix
Import the `html` package at the top of `comment_view.go`:
```go
import (
	"fmt"
	"html"
	"net/http"
)
```

Then modify the `Render` method to escape the HTML entities:
```go
func (v *CommentView) Render(c Comment) error {
	v.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf("<div class=\"comment\"><h3>%s says:</h3><p>%s</p></div>", html.EscapeString(c.Author), html.EscapeString(c.Excerpt))
	_, err := v.w.Write([]byte(html))
	return err
}
```

## Explanation
The root cause is that untrusted user input (`Author` and `Excerpt`) is directly embedded into HTML markup without encoding. An attacker can inject arbitrary HTML and JavaScript by crafting a form submission with payload like `<script>alert('xss')</script>` in the author or message field.

The fix applies HTML entity encoding using `html.EscapeString()` to both `c.Author` and `c.Excerpt` before they are interpolated into the HTML template string. This converts dangerous characters like `<`, `>`, `"`, `'`, and `&` into their HTML entity equivalents (`&lt;`, `&gt;`, `&quot;`, `&#39;`, `&amp;`), ensuring the user input is rendered as literal text rather than interpreted as HTML or script markup. The standard library's `html.EscapeString()` is the idiomatic Go solution for this class of vulnerability when outputting to HTML context.
