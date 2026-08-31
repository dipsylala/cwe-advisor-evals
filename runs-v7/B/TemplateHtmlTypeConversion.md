## Verdict

The finding is confirmed. Untrusted user input from `r.FormValue("reviewText")` is wrapped in `template.HTML()`, disabling automatic escaping and allowing XSS injection via the template sink.

## Source

HTTP form parameter `reviewText` accessed via `r.FormValue("reviewText")` at line 16. This is attacker-controlled user input with no validation.

## Fix

**Original code (lines 18–23):**
```go
data := struct {
	Body template.HTML
}{
	// SAST FINDING: CWE-79...
	Body: template.HTML(reviewText),
}
```

**Fixed code:**
```go
data := struct {
	Body string
}{
	Body: reviewText,
}
```

Change the `Body` field type from `template.HTML` to `string` and remove the `template.HTML()` wrapper. The `html/template` package (already imported at line 4) will automatically escape HTML entities in string values when rendering `{{.Body}}` in the template's HTML body context.

## Explanation

The vulnerability occurs because `template.HTML()` tells the Go templating engine to treat the wrapped value as pre-sanitized and safe, bypassing all escaping. Since `reviewText` comes directly from untrusted user input with no validation, an attacker can inject malicious scripts — for example, `<script>alert('xss')</script>` — which will execute in the victim's browser.

The fix changes the field type to `string`, which causes `html/template` to automatically apply context-aware HTML entity encoding when rendering. Characters like `<`, `>`, `&`, and quotes are escaped to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`), preventing script injection while preserving the intended display of legitimate content that happens to contain these characters.

## Behaviour changes

- User reviews containing HTML-special characters (e.g., `a < b`, `foo & bar`) will now render with those characters escaped, displaying as text rather than as HTML syntax. This is the correct and safe behaviour.
- XSS injection attempts (e.g., `<img onerror=alert(1)>`) will no longer execute; they will render as escaped text.
- No other behaviour is affected; legitimate review text displays correctly.
