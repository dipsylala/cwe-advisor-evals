## Verdict

Exploitable

## Source

`request.args.get("label", "")` retrieves untrusted user input from the query parameter.

## Fix

**Vulnerable Code:**
```python
from flask import Flask, request
from markupsafe import Markup

@app.route("/tickets/status")
def ticket_status():
    ticket_id = request.args.get("ticket_id", "")
    label = request.args.get("label", "Ticket")
    status = lookup_ticket_status(ticket_id)

    # The caller-supplied label is wrapped in Markup() so it can sit next to
    # the status badge without Jinja2 escaping it when the page is rendered.
    safe_label = Markup(label)  # VULNERABLE: Markup() disables escaping on untrusted data
    banner = f"<div class='ticket-banner'><span class='label'>{safe_label}</span>: {status}</div>"

    return f"<html><body>{banner}</body></html>"
```

**Fixed Code:**
```python
from flask import Flask, request
import html

@app.route("/tickets/status")
def ticket_status():
    ticket_id = request.args.get("ticket_id", "")
    label = request.args.get("label", "Ticket")
    status = lookup_ticket_status(ticket_id)

    # Properly escape the caller-supplied label to prevent XSS injection
    safe_label = html.escape(label)
    banner = f"<div class='ticket-banner'><span class='label'>{safe_label}</span>: {status}</div>"

    return f"<html><body>{banner}</body></html>"
```

## Explanation

The vulnerability occurs because `Markup(label)` marks untrusted user input as safe HTML, disabling escaping and allowing an attacker to inject arbitrary HTML and JavaScript. By replacing `Markup()` with `html.escape()`, the label is properly HTML-encoded so that special characters like `<`, `>`, `&`, and quotes are converted to their HTML entities (`&lt;`, `&gt;`, `&amp;`, etc.). This ensures the label is treated as data, not executable code, preventing XSS injection while preserving the original functionality of displaying the user-supplied label safely in the HTML context.

## Behaviour changes

None. The fix preserves the sink contract: the string is still embedded in the f-string and returned as HTML. The only change is that special characters in the label are now properly escaped, so `<img src=x onerror=alert('XSS')>` will render as text displaying the literal HTML tags, rather than executing JavaScript. Legitimate content containing `<`, `>`, `&`, and quotes will continue to render correctly but with HTML entities visible in the rendered output, which is the correct and expected behavior for user-supplied text in an HTML context.
