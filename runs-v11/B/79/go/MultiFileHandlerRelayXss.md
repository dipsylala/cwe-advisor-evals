## Verdict

Exploitable. User-controlled form data flows from the HTTP request through `FeedbackService` and `CommentFormatter` to `CommentView.Render()` where it is directly interpolated into HTML without escaping, creating a context where script injection is possible.

## Source

Entry points:
- `feedback_handler.go` lines 19-20: `r.FormValue("author")` and `r.FormValue("message")` read untrusted form data
- Data flows through `FeedbackRequest` struct to `FeedbackService.HandleSubmission()`
- `CommentFormatter.PrepareForDisplay()` trims and truncates but does not escape for HTML output
- `CommentView.Render()` receives the formatted `Comment` object

The sink at `comment_view.go` line 22 interpolates `c.Author` and `c.Excerpt` into an HTML string using `fmt.Sprintf`, then line 24 writes the unescaped result to the response via `v.w.Write()`.

## Fix

**Before (vulnerable):**
```go
func (v *CommentView) Render(c Comment) error {
	v.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf("<div class=\"comment\"><h3>%s says:</h3><p>%s</p></div>", c.Author, c.Excerpt)
	_, err := v.w.Write([]byte(html))
	return err
}
```

**After (fixed):**
```go
package feedback

import (
	"fmt"
	"html"
	"net/http"
)

func (v *CommentView) Render(c Comment) error {
	v.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf("<div class=\"comment\"><h3>%s says:</h3><p>%s</p></div>", 
		html.EscapeString(c.Author), html.EscapeString(c.Excerpt))
	_, err := v.w.Write([]byte(html))
	return err
}
```

## Explanation

The vulnerability occurs because user-supplied `Author` and `Excerpt` values are directly embedded into an HTML string without any encoding. This allows an attacker to inject HTML/JavaScript by submitting form data containing tags like `<script>` or event handlers like `onload=alert(1)`. 

The fix applies Go's standard `html.EscapeString()` function to both user-controlled fields before interpolation. This function encodes the five characters that have special meaning in HTML contexts: `<` → `&lt;`, `>` → `&gt;`, `&` → `&amp;`, `"` → `&#34;`, and `'` → `&#39;`. After escaping, any injected markup is treated as plain text and displayed harmlessly in the browser rather than executed as code.

## Behaviour changes

The output HTML will differ in appearance when user input contains characters that require HTML entity encoding. For example, if a user's name is `Alice & Bob`, the rendered output will display the escaped form `Alice &amp; Bob` in the HTML. This is the correct and necessary behavior: legitimate content containing `<`, `&`, quotes, and similar characters must be escaped to prevent interpretation as markup. No legitimate functionality is lost; users will see the correct content rendered safely.
