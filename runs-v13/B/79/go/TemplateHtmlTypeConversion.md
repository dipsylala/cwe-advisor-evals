## Verdict

Confirmed exploitable. Untrusted user input from an HTTP form is explicitly marked as safe HTML via `template.HTML()` cast, disabling the template engine's auto-escaping. This allows arbitrary JavaScript injection.

## Source

Line 16: `reviewText := r.FormValue("reviewText")` - untrusted form parameter.

Line 22: `Body: template.HTML(reviewText)` - the taint sink. The `template.HTML()` constructor explicitly disables escaping for this value, telling html/template "this is safe HTML, render it as-is."

## Fix

Change the struct field type from `template.HTML` to `string`, and remove the `template.HTML()` cast:

```go
data := struct {
	Body string
}{
	Body: reviewText,
}
```

The html/template package will automatically apply context-aware escaping. Since `{{.Body}}` appears in an HTML body context (inside `<div class="review-body">{{.Body}}</div>`), the template engine will escape HTML metacharacters (`<`, `>`, `&`, `"`, `'`) automatically, rendering user input as text rather than executable code.

## Explanation

The vulnerability stems from wrapping untrusted input in `template.HTML()`, which is an explicit escape-disabling mechanism. The type system exists precisely to prevent this: `template.HTML` signals "I have verified this is safe HTML" to the template engine, bypassing all escaping.

By changing the struct field to `string` and removing the cast, the input flows through html/template's context-aware escaper. The template's position rule - data in HTML body text - triggers automatic escaping. An attacker's payload like `<img onerror="alert('XSS')">` will be rendered as literal text: `&lt;img onerror=&quot;alert(&#39;XSS&#39;)&quot;&gt;`, disarming the injection.

## Behaviour changes

- **Output encoding**: User text containing HTML metacharacters (`<`, `>`, `&`) will now be escaped and appear as plain text rather than interpreted as markup.
- **Legitimate content preservation**: Text that should render literally (e.g., "Learn & do <better>") remains readable, just escaped so browsers treat it as data, not code.
- **No data loss**: The review text is still rendered and visible; only its interpretation changes from code to text.
- **No API changes**: The handler's signature and response flow remain unchanged; only the internal struct field type changes.
