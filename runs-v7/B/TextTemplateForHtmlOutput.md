## Verdict
Exploitable

## Source
Query parameter `subject` from `r.URL.Query().Get("subject")` at line 18

## Fix
**Vulnerable code** (line 5):
```go
import (
	"net/http"
	"text/template"
)
```

**Fixed code**:
```go
import (
	"net/http"
	"html/template"
)
```

## Explanation
The vulnerability occurs because `text/template` does not perform automatic output encoding. The untrusted `subject` parameter is passed directly into the template at line 12 (`{{.Subject}}`) and rendered unencoded into the HTML response. An attacker can inject arbitrary HTML and JavaScript by supplying a payload like `<script>alert('xss')</script>`. 

Replacing `text/template` with `html/template` enables context-aware auto-escaping: special characters like `<`, `>`, `&`, and quotes are automatically encoded as HTML entities (`&lt;`, `&gt;`, `&amp;`, `&#34;`, etc.), preventing the browser from interpreting them as markup or script code. The template syntax and data binding remain identical; `html/template` is a drop-in replacement that adds the escaping layer.

## Behaviour changes
None. The `html/template` package is a superset of `text/template` with added auto-escaping. Legitimate content containing `<`, `>`, or `&` characters will render as text rather than markup—for example, a subject like `"User & Admin"` will display correctly as written instead of being interpreted as an HTML entity reference. This is the intended security behavior and not a functional regression.
