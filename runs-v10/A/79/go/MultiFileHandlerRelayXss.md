## Verdict
Confirmed XSS (CWE-79). User-controlled input from HTTP request parameters flows through the service layer without HTML escaping and is written directly into an HTML response.

## Source
Input originates in `feedback_handler.go` line 19-20:
- `r.FormValue("author")` 
- `r.FormValue("message")`

These values are placed into a `FeedbackRequest` and passed to `FeedbackService.HandleSubmission()`. The `CommentFormatter.PrepareForDisplay()` method performs only text normalization (trimming, truncating) without HTML escaping. The unescaped values then flow into the `Comment` struct fields `Author` and `Excerpt`, which are subsequently interpolated into HTML in `comment_view.go`.

## Fix
Import `html/template` at the top of `comment_view.go`:
```go
import (
	"fmt"
	"html"
	"net/http"
)
```

In the `Render` method, escape both `c.Author` and `c.Excerpt` using `html.EscapeString()` before interpolating into the HTML template:
```go
func (v *CommentView) Render(c Comment) error {
	v.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf("<div class=\"comment\"><h3>%s says:</h3><p>%s</p></div>", 
		html.EscapeString(c.Author), 
		html.EscapeString(c.Excerpt))
	_, err := v.w.Write([]byte(html))
	return err
}
```

## Explanation
The vulnerability occurs because user input is interpolated directly into an HTML string without sanitization. The `html.EscapeString()` function converts HTML metacharacters (`<`, `>`, `"`, `&`) into their corresponding entities (`&lt;`, `&gt;`, `&quot;`, `&amp;`), preventing the injected content from being interpreted as HTML or JavaScript.

For example, an attacker input like `<img src=x onerror=alert('XSS')>` becomes `&lt;img src=x onerror=alert('XSS')&gt;` in the response, rendering it as plain text rather than executable code.

This fix applies `html.EscapeString()` at the point where HTML is constructed, which is the appropriate layer for this pattern of manual HTML string building. Alternative approaches include using `html/template` package with automatic escaping, but the string interpolation approach here requires explicit escaping at the sink.
