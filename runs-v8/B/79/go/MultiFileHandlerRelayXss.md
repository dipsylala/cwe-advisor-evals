## Verdict

Exploitable. Untrusted user input (author name and message excerpt) flows from form fields through to HTML output without encoding, enabling arbitrary script injection.

## Source

HTTP form fields `author` and `message` from `feedback_handler.go` lines 19-20, passed through `FeedbackService` to `CommentFormatter` (which performs no encoding), then to `CommentView.Render()`.

## Fix

**Vulnerable code** (comment_view.go):
```go
package feedback

import (
	"fmt"
	"net/http"
)

func (v *CommentView) Render(c Comment) error {
	v.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf("<div class=\"comment\"><h3>%s says:</h3><p>%s</p></div>", c.Author, c.Excerpt)
	_, err := v.w.Write([]byte(html))
	return err
}
```

**Fixed code** (comment_view.go):
```go
package feedback

import (
	"html/template"
	"net/http"
)

func (v *CommentView) Render(c Comment) error {
	v.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t, err := template.New("comment").Parse(`<div class="comment"><h3>{{.Author}} says:</h3><p>{{.Excerpt}}</p></div>`)
	if err != nil {
		return err
	}
	return t.Execute(v.w, c)
}
```

## Explanation

The original code built HTML via string concatenation using `fmt.Sprintf`, then wrote the unescaped string directly to the response. The `Author` and `Excerpt` fields contain untrusted user input that an attacker can use to inject script tags or event handlers.

The fix replaces this with Go's `html/template` package, which performs automatic, context-aware escaping of all template variables. When `{{.Author}}` and `{{.Excerpt}}` are rendered, special characters (`<`, `>`, `&`, `"`, `'`) are escaped to their HTML entity equivalents, preventing the template data from being interpreted as HTML markup or script. This ensures that legitimate content containing these characters is displayed safely while blocking XSS payloads like `<script>alert('xss')</script>` or `"><svg onload=alert(1)>`.

## Behaviour changes

- **Import change**: Replaced `"fmt"` with `"html/template"`. Reason: Template package is required for context-aware escaping.
- **Error handling**: Template parsing errors are now caught and returned. Reason: `template.New().Parse()` can fail and must be handled; this is a small additional error surface but necessary for the escaping guarantee.
- **Output escaping**: Special characters in `Author` and `Excerpt` are now HTML-escaped. Reason: This is the fix itself—it prevents script injection.
- **Sink contract preserved**: Response is still written to `v.w` with `Content-Type: text/html; charset=utf-8`. The output destination, encoding declaration, and HTML structure remain identical; only the encoding of the data values changes.
