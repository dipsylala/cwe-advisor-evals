## Verdict
Confirmed. Untrusted user input from `r.FormValue()` is wrapped directly in `template.HTML()`, which bypasses `html/template`'s auto-escaping. Attackers can inject arbitrary HTML and JavaScript by submitting review text containing script tags or event handlers.

## Source
Line 16: `reviewText := r.FormValue("reviewText")` — untrusted input from HTTP form parameter.

Line 22: `Body: template.HTML(reviewText)` — the taint sink. `template.HTML()` tells the template engine to treat the value as already-safe, skipping escaping when rendered at line 11 (`{{.Body}}`).

## Fix
**Changed lines 19 and 22:**

```go
// BEFORE
data := struct {
	Body template.HTML
}{
	Body: template.HTML(reviewText),
}

// AFTER
data := struct {
	Body string
}{
	Body: reviewText,
}
```

Change the `Body` field type from `template.HTML` to `string`, and pass `reviewText` directly without wrapping it in `template.HTML()`. This allows `html/template` to apply context-aware HTML escaping when rendering the template.

## Explanation
The code uses `html/template`, which automatically escapes data based on context (HTML body, attribute, JavaScript, CSS, URL). However, `template.HTML()` is an explicit escape bypass — it signals to the template engine that the value is already safe HTML and should not be escaped.

By removing the `template.HTML()` wrapper and using a plain `string` field, `html/template` will automatically escape special characters (`<`, `>`, `&`, `"`, `'`) when rendering `{{.Body}}` in the template. This prevents script injection while preserving the review text content.

The fix relies on `html/template`'s built-in context-aware encoding (the primary defence per CWE-79 guidance) and does not require additional libraries.

## Behaviour changes
- Special characters in review text are now HTML-encoded (e.g., `<script>` becomes `&lt;script&gt;`)
- Legitimate review text containing `&`, `<`, `>`, quotes, or other HTML metacharacters will render correctly as text, not as HTML markup
- XSS payloads (e.g., `"><svg onload=alert(1)>`, `<img src=x onerror=...>`) are neutralized by escaping
- The review display layout and structure remain unchanged; only the user-supplied content is escaped
