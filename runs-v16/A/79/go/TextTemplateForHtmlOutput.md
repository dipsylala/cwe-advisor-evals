## Verdict

Confirmed. The code uses `text/template` to render user-supplied input directly into HTML without escaping, allowing arbitrary script injection.

## Source

Line 28 executes the template with user input from the query string:

```go
subject := r.URL.Query().Get("subject")
```

This unescaped input flows into the template via the `Subject` field at line 12, where `text/template` renders it as-is without HTML escaping.

## Fix

Replace `text/template` with `html/template` in the import:

```go
import (
	"html/template"
	"net/http"
)
```

The rest of the code remains unchanged. `html/template` automatically escapes template data when rendering to prevent XSS.

## Explanation

The `text/template` package performs no escaping by default and is unsafe for HTML contexts. The `html/template` package is a drop-in replacement that escapes contextually—converting `<`, `>`, `&`, `"`, and `'` to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`) when substituting data into templates. This prevents the injected script from executing: `?subject=<script>alert('xss')</script>` becomes the literal string displayed in the page, not executable code. This is the standard Go idiom for safe HTML generation in request handlers.
