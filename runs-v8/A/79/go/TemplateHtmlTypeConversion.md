## Verdict
CONFIRMED: Cross-site Scripting vulnerability via unsafe `template.HTML` type conversion of untrusted user input.

## Source
Line 22 converts user-supplied form data directly to `template.HTML` without sanitization:
```go
reviewText := r.FormValue("reviewText")
// ...
Body: template.HTML(reviewText),
```

The `template.HTML` type instructs the Go template engine to treat content as pre-escaped and output it as-is, bypassing automatic escaping. An attacker can inject arbitrary JavaScript.

## Fix
Remove the `template.HTML` type conversion and use plain `string` instead, allowing the template engine to automatically escape HTML special characters:

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

The `html/template` package automatically escapes string values by default, converting `<`, `>`, `&`, `"`, and `'` to their HTML entity equivalents, neutralizing injected scripts.

## Explanation
`template.HTML` is a Go type that signals "this string is already HTML-escaped, do not escape it again." Casting untrusted user input to this type bypasses the template engine's security boundary. By using a plain string type instead, the template engine applies its default context-aware escaping rules, rendering user-controlled content safe within HTML context.
