## Verdict
CONFIRMED

## Source
E:/Github/cwe-advisor/evals/cases/79/go/TemplateHtmlTypeConversion/TemplateHtmlTypeConversion.go, line 22

The vulnerability occurs where untrusted user input from `r.FormValue("reviewText")` is cast directly to `template.HTML` without sanitization. The `template.HTML` type signals to Go's template engine that content is already safe HTML and should not be escaped.

An attacker can submit review text containing JavaScript, such as `<img src=x onerror="alert('XSS')">`, which will be rendered unescaped in the response.

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
The fix removes the `template.HTML` type cast and changes the struct field from `template.HTML` to `string`. 

When a field is typed as `string` in the data passed to an HTML template, Go's `html/template` package automatically escapes HTML special characters (`<`, `>`, `&`, `"`, `'`) when rendering the `{{.Body}}` expression. This prevents the injected JavaScript from being interpreted as code.

The attacker's payload `<img src=x onerror="alert('XSS')">` will be rendered as escaped HTML (`&lt;img src=x onerror=&quot;alert(&#39;XSS&#39;)&quot;&gt;`), displaying safely as text to the user rather than executing as a script.
