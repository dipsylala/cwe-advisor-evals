## Verdict

Exploitable

## Source

`subject := r.URL.Query().Get("subject")` on line 18 — untrusted user-supplied input from URL query parameter

## Fix

**Vulnerable code (line 5):**
```go
import (
	"net/http"
	"text/template"
)
```

**Fixed code:**
```go
import (
	"net/http"
	"html/template"
)
```

Replace `text/template` with `html/template`. The template itself and all subsequent code remain unchanged; `html/template` is a drop-in replacement that automatically applies context-aware output encoding.

## Explanation

The vulnerability occurs because `text/template` does not perform any HTML escaping. When the untrusted `Subject` value is rendered into the HTML body via `{{.Subject}}` on line 12, special characters like `<`, `>`, `&`, and quotes are written as-is to the HTTP response. An attacker can exploit this by passing `subject=<script>alert('xss')</script>` in the query parameter, causing the script to execute in the victim's browser. Switching to `html/template` closes this gap: the package automatically escapes all template data based on context (HTML body, attributes, JavaScript, CSS, URLs). The `{{.Subject}}` placeholder will now render dangerous characters as HTML entities (`&lt;`, `&gt;`, etc.), preventing script injection. This fix is a simple import substitution because `html/template` provides an identical API to `text/template`; no changes to the template content or the calling code are required.

## Behaviour changes

None — `html/template` has an identical public API to `text/template` and produces the same final output for safe input. The only change is automatic encoding of unsafe characters in template data, which is the intended fix. Legitimate content containing `<`, `&`, `"`, or `'` will render correctly as HTML entities while remaining safe.
