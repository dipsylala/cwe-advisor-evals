## Verdict
Exploitable

## Source
`label` parameter from user input via `request.args.get("label", "")` (line 14)

## Fix

**Vulnerable code (line 20):**
```python
safe_label = Markup(label)
```

**Fixed code:**
```python
import html
...
safe_label = html.escape(label)
```

Alternatively, enable template auto-escaping and use Flask's `render_template()` instead of building HTML strings directly:

```python
from flask import render_template
...
return render_template('ticket_status.html', safe_label=label, status=status)
```
(with `ticket_status.html` containing `{{ safe_label }}` which auto-escapes by default)

## Explanation

The vulnerable code wraps user input in `Markup()` without escaping, which marks the untrusted string as safe HTML and prevents any encoding. This allows attackers to inject arbitrary HTML and JavaScript. The fix uses `html.escape()` to convert HTML special characters (`<`, `>`, `&`, `"`, `'`) to entity references, ensuring the label is rendered as literal text rather than executable code. Alternatively, using Flask's template engine with auto-escaping enabled provides automatic protection without requiring manual escaping on each variable.

## Behaviour changes

- The `label` parameter is now HTML-entity-encoded: `<script>` becomes `&lt;script&gt;` and is displayed as text rather than executed.
- Legitimate content containing `<`, `>`, `&`, and quotes is displayed correctly as text without rendering as HTML tags or breaking attribute syntax.
- The application's functional behaviour is unchanged; only the injection vector is eliminated.
