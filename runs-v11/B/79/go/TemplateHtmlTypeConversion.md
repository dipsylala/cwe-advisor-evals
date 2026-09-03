## Verdict

Exploitable. User input from `r.FormValue("reviewText")` flows directly to line 22 where it is cast to `template.HTML`, disabling the template engine's auto-escaping, and renders unescaped in the HTML response at line 11.

## Source

Line 16: `reviewText := r.FormValue("reviewText")` — untrusted HTTP form parameter.

## Fix

**Vulnerable code (line 22):**
```go
Body: template.HTML(reviewText),
```

**Fixed code (line 22):**
```go
Body: reviewText,
```

**Complete fixed context (lines 18–23):**
```go
data := struct {
    Body string
}{
    Body: reviewText,
}
```

## Explanation

The fix removes the `template.HTML()` cast that disables auto-escaping. By assigning `reviewText` as a plain `string` to a `string` field, the `html/template` engine (already imported on line 4) automatically escapes HTML special characters when rendering `{{.Body}}` in the template. This prevents the attacker from injecting script tags or event handlers while preserving legitimate content containing `<`, `&`, `"`, and `'`.

## Behaviour changes

The struct field type changes from `template.HTML` to `string`. HTML special characters in user input (`<`, `>`, `&`, `"`, `'`) will now be escaped to their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`) when rendered. This is the correct and intended behaviour for untrusted input in HTML context—it prevents XSS while displaying user-provided content safely.
