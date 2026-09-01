## Verdict

Real XSS vulnerability confirmed. Untrusted form input is wrapped in `template.HTML()`, which disables escaping and allows script injection.

## Source

Line 16: `reviewText := r.FormValue("reviewText")` retrieves untrusted user input from the HTTP request.

## Fix

```go
data := struct {
	Body string
}{
	Body: reviewText,
}
```

Change line 19 from `Body template.HTML` to `Body string`, and remove the `template.HTML()` wrapper on line 22.

## Explanation

The Go `html/template` package applies context-aware escaping automatically to string values. By removing the `template.HTML()` wrapper and letting the field type be plain `string`, the template engine will escape HTML special characters like `<`, `>`, `&`, and quotes, converting them to their entity forms (`&lt;`, `&gt;`, `&amp;`, `&quot;`). This prevents injected script tags from being interpreted as code. The `template.HTML()` type explicitly signals "this content is safe HTML and should not be escaped" - a promise that must never be made with untrusted input.

## Behaviour changes

- **Output encoding**: User-supplied text containing `<script>alert('xss')</script>` will be rendered as the literal string `&lt;script&gt;alert('xss')&lt;/script&gt;` in the HTML body, displayed as text rather than executed.
- **Legitimate content**: User input with ampersands, angle brackets, or quotes needed in display text will render correctly; the entities will be decoded by the browser to display the original characters.
- **Performance**: Negligible - escaping is performed once per template render.
- **API contract**: The data struct field type changes from `template.HTML` to `string`, which is transparent to callers passing data through `Execute()`.
