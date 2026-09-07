## Verdict

Exploitable. User-supplied input from the query parameter flows through to an unescaped template sink.

## Source

Line 18: `subject := r.URL.Query().Get("subject")`

User-controlled query parameter `subject` is extracted without validation or encoding.

## Fix

**Vulnerable code:**

```go
import (
	"net/http"
	"text/template"
)

var ticketPage = template.Must(template.New("ticket").Parse(`
	<html>
		<body>
			<h2>Ticket Status</h2>
			<p>Subject: {{.Subject}}</p>
		</body>
	</html>
`))
```

**Fixed code:**

```go
import (
	"html/template"
	"net/http"
)

var ticketPage = template.Must(template.New("ticket").Parse(`
	<html>
		<body>
			<h2>Ticket Status</h2>
			<p>Subject: {{.Subject}}</p>
		</body>
	</html>
`))
```

Change the import from `text/template` to `html/template`. The rest of the code remains unchanged. The `html/template` package provides automatic context-aware HTML escaping of template actions, so `{{.Subject}}` will escape HTML metacharacters in the output.

## Explanation

The vulnerability occurs because `text/template` does not escape output for HTML rendering. When user input from `r.URL.Query().Get("subject")` is passed into the template and rendered with `ticketPage.Execute(w, data)`, a payload like `<script>alert('xss')</script>` is inserted verbatim into the HTML response without escaping. 

The fix replaces `text/template` with `html/template`, which automatically applies context-aware escaping to all template actions. The same template syntax and structure work identically, but `html/template` treats `{{.Subject}}` as an HTML body context and escapes the value so that `<`, `>`, `&`, `"`, and `'` are converted to HTML entities (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), preventing script injection. This preserves the functionality while eliminating the XSS vector.

## Behaviour changes

None. Both `text/template` and `html/template` have the same `Execute()` method signature, parse syntax, and error behavior. The only change is the automatic HTML escaping applied by `html/template`, which is the desired security fix and does not alter legitimate rendering of content containing the characters that are escaped (e.g., `<div>` in a subject will display as literal text `&lt;div&gt;`, not as an HTML element).
