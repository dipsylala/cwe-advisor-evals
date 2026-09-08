## Verdict

exploitable

- cwe_id: CWE-79
- location: TemplateHtmlTypeConversion.go:22 (sink is line 26, `reviewTmpl.Execute(w, data)`, rendering the value wrapped at line 22)
- confidence: high

## Source

`r.FormValue("reviewText")` at line 16 - attacker-controlled form data submitted to the `/reviews` HTTP handler, with no validation or encoding applied before use.

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

The `Body` field was declared as `template.HTML`, and `html/template` treats any value of that type as pre-escaped, trusted markup - it is emitted into the response verbatim, byte for byte, bypassing the package's context-aware auto-escaping entirely. Wrapping the raw form value `reviewText` in `template.HTML(reviewText)` at line 22 turned attacker-controlled text into a live HTML/script injection sink: a submission such as `<script>document.cookie</script>` in `reviewText` renders and executes in the viewer's browser exactly as submitted. The fix changes the struct field's type from `template.HTML` to `string` and assigns `reviewText` to it directly, with no wrapping conversion. `html/template` auto-escapes any field typed as plain `string` for its HTML-body context when the template executes, so `<`, `>`, `&`, and quote characters in the review text are rendered as inert, visible text (e.g. `&lt;script&gt;...`) rather than parsed as markup. This is the primary defence the loaded Go guidance for CWE-79 gives: never wrap untrusted input in `template.HTML`, and let `html/template`'s escaper handle encoding rather than hand-rolling or bypassing it. A customer review is expected to be user-typed text, not intentional rich HTML, so no sanitizer (e.g. bluemonday) is warranted here - that pattern applies only where rich HTML input must be preserved, which is not this case.

## Behaviour changes

- Field type `Body template.HTML` -> `Body string`: required to re-enable auto-escaping; this is the fix itself, not a side effect.
- Rendered output for text containing `<`, `>`, `&`, or quotes now displays as escaped entities (e.g. a literal `<` submitted in a review shows as `<` in the page, not as a parsed tag) instead of being interpreted as HTML. This is the intended effect of closing the injection: legitimate review text with no markup renders identically to before; only text that would have been interpreted as markup or script now displays as literal text instead of executing.
- No other arguments, return values, headers, or error handling were changed. `reviewTmpl.Execute`'s ignored error return, the `Content-Type: text/html` header, and the handler/routing structure are all unchanged from the original.

## Verification

Copied the fixed file to a scratch Go module outside the repository and ran `go vet ./...` (exit 0, no diagnostics) and `go build .` (exit 0, compiles cleanly) against Go 1.25.5. No new imports, packages, or APIs were introduced - the fix only narrows an existing struct field's type and removes the `template.HTML(...)` conversion, so no additional name-existence check was needed.
