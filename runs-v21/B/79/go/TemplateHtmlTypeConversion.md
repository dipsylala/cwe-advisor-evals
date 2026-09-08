## Verdict

**VULNERABLE** - CWE-79 confirmed. Untrusted user input from `r.FormValue("reviewText")` is wrapped in `template.HTML()` on line 22, which explicitly disables `html/template`'s context-aware escaping. The template then renders this unescaped value directly into HTML, allowing XSS injection.

## Source

Line 16: `reviewText := r.FormValue("reviewText")` — untrusted user input from HTTP form.

## Fix

### File: TemplateHtmlTypeConversion.go

```go
package main

import (
	"html/template"
	"net/http"
)

var reviewTmpl = template.Must(template.New("review").Parse(`
	<html><body>
		<h3>Customer Review</h3>
		<div class="review-body">{{.Body}}</div>
	</body></html>
`))

func postReviewHandler(w http.ResponseWriter, r *http.Request) {
	reviewText := r.FormValue("reviewText")

	data := struct {
		Body string
	}{
		Body: reviewText,
	}

	w.Header().Set("Content-Type", "text/html")
	reviewTmpl.Execute(w, data)
}

func main() {
	http.HandleFunc("/reviews", postReviewHandler)
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

The vulnerability was that `template.HTML()` on line 22 explicitly wrapped the untrusted `reviewText` in a type that tells `html/template` to bypass escaping. The fix removes this wrapper and changes the struct field type from `template.HTML` to `string`. Now `html/template` will automatically apply context-aware HTML escaping when rendering `{{.Body}}` in the template, converting dangerous characters like `<`, `>`, `&`, and quotes to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`). This prevents the injected script from executing while preserving legitimate content.

## Behaviour changes

- User input containing `<script>alert('XSS')</script>` will now render as `&lt;script&gt;alert('XSS')&lt;/script&gt;` in the browser, displayed as plain text rather than executed as code.
- Legitimate content with special characters (e.g., `Tom & Jerry's review`) will render correctly with proper escaping (`Tom &amp; Jerry&#39;s review`).
- The template's rendering behavior is unchanged — the value still flows to the output — but is now safe against injection.
