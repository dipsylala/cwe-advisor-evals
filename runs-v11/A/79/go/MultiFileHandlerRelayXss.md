## Verdict

**Confirmed.** User-supplied data from the feedback form is passed through the formatter and directly interpolated into HTML without escaping, enabling stored XSS attacks.

## Source

The vulnerability originates in `SubmitFeedbackHandler` (feedback_handler.go, lines 19-20), where form input is read:
```
Author:  r.FormValue("author"),
Message: r.FormValue("message"),
```

This untrusted data flows through `FeedbackService.HandleSubmission()` → `CommentFormatter.PrepareForDisplay()` → `CommentView.Render()`.

The sink is in `comment_view.go` at line 22, where `fmt.Sprintf` directly interpolates the unescaped `c.Author` and `c.Excerpt` into an HTML string, then writes it to the response at line 24.

## Fix

Import the `html` package and escape both user-supplied fields before interpolating them into the HTML template. Replace line 22:

```go
import (
	"fmt"
	"html"
	"net/http"
)

// In Render method:
html_escaped := fmt.Sprintf("<div class=\"comment\"><h3>%s says:</h3><p>%s</p></div>", html.EscapeString(c.Author), html.EscapeString(c.Excerpt))
_, err := v.w.Write([]byte(html_escaped))
```

Or more cleanly, extract the escaping to avoid repeating the template:

```go
import (
	"fmt"
	"html"
	"net/http"
)

// In Render method:
v.w.Header().Set("Content-Type", "text/html; charset=utf-8")
author := html.EscapeString(c.Author)
excerpt := html.EscapeString(c.Excerpt)
htmlOutput := fmt.Sprintf("<div class=\"comment\"><h3>%s says:</h3><p>%s</p></div>", author, excerpt)
_, err := v.w.Write([]byte(htmlOutput))
return err
```

## Explanation

The `CommentFormatter` explicitly documents that it does not HTML-encode the output ("Neither step encodes the text for HTML output - that is left to whatever renders the comment"). The `CommentView.Render()` method is where that encoding should happen, since it is building the final HTML.

Go's `html.EscapeString()` function converts characters like `<`, `>`, `&`, `"`, and `'` to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), preventing injected HTML/JavaScript from being interpreted as markup. This ensures that if an attacker submits a comment with author name `<img src=x onerror=alert('xss')>`, it will be rendered as harmless text rather than executed.

Applying HTML escaping at the point of rendering (the sink) is the correct defense here, as it centralizes the encoding responsibility where the data is actually being written to HTML context.
