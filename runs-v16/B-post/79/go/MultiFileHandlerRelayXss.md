## Verdict

Exploitable. Untrusted user input from HTTP form fields (Author and Excerpt/Message) flows directly into HTML concatenation via `fmt.Sprintf`, then to `w.Write` without any HTML encoding, allowing XSS injection into the response.

## Source

HTTP form parameters in `feedback_handler.go` line 19: `r.FormValue("author")` and `r.FormValue("message")`, which become `Comment.Author` and `Comment.Excerpt` after preparation.

## Fix

**Vulnerable code:**

```go
func (v *CommentView) Render(c Comment) error {
	v.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf("<div class=\"comment\"><h3>%s says:</h3><p>%s</p></div>", c.Author, c.Excerpt)
	// SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
	_, err := v.w.Write([]byte(html))
	return err
}
```

**Fixed code:**

```go
func (v *CommentView) Render(c Comment) error {
	v.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t := template.Must(template.New("comment").Parse(
		`<div class="comment"><h3>{{.Author}} says:</h3><p>{{.Excerpt}}</p></div>`,
	))
	return t.Execute(v.w, c)
}
```

Update imports from:
```go
import (
	"fmt"
	"net/http"
)
```

to:
```go
import (
	"html/template"
	"net/http"
)
```

## Explanation

The fix replaces unsafe string concatenation with `html/template`, which performs automatic context-aware HTML escaping on all data bound to template placeholders. When `{{.Author}}` and `{{.Excerpt}}` are evaluated, their special characters (`<`, `>`, `&`, quotes, etc.) are HTML-encoded to safe entity references (`&lt;`, `&gt;`, `&amp;`, `&#34;`, etc.), preventing the injected content from being interpreted as HTML or JavaScript. The template is executed directly to the response writer, preserving the same output behavior while eliminating the XSS window.

## Behaviour changes

None. The output remains identical for legitimate content — an HTML fragment with the author name and excerpt wrapped in div and paragraph tags. The only change is that special characters in Author and Excerpt are now encoded, which prevents their interpretation as HTML/JavaScript and is transparent to the page rendering.

