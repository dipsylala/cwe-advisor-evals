## Verdict

The application is vulnerable to reflected cross-site scripting (XSS) through the user-supplied `label` parameter. By wrapping the label in `Markup()`, the code explicitly bypasses Flask's auto-escaping protection, allowing attackers to inject arbitrary HTML and JavaScript into the response.

## Source

```python
def ticket_status():
    ticket_id = request.args.get("ticket_id", "")
    label = request.args.get("label", "Ticket")
    status = lookup_ticket_status(ticket_id)

    # The caller-supplied label is wrapped in Markup() so it can sit next to
    # the status badge without Jinja2 escaping it when the page is rendered.
    safe_label = Markup(label)
    banner = f"<div class='ticket-banner'><span class='label'>{safe_label}</span>: {status}</div>"

    return f"<html><body>{banner}</body></html>"
```

## Fix

Remove the `Markup()` call and use Flask's template rendering system, which applies auto-escaping by default:

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

def lookup_ticket_status(ticket_id):
    return "open"

@app.route("/tickets/status")
def ticket_status():
    ticket_id = request.args.get("ticket_id", "")
    label = request.args.get("label", "Ticket")
    status = lookup_ticket_status(ticket_id)

    template = """
    <html><body>
        <div class='ticket-banner'>
            <span class='label'>{{ label }}</span>: {{ status }}
        </div>
    </body></html>
    """

    return render_template_string(template, label=label, status=status)
```

## Explanation

The root cause is the explicit use of `Markup()` on untrusted user input. `Markup()` tells Flask/Jinja2 that the string is safe HTML and should not be escaped. When this marked-safe string is embedded in the response, any HTML tags or JavaScript in the user's input will be executed by the browser.

The fix replaces string formatting with Jinja2 template rendering. Template variables like `{{ label }}` are automatically HTML-escaped by Flask's default auto-escaping behavior, converting characters like `<`, `>`, and `"` to their HTML entity equivalents (`&lt;`, `&gt;`, `&quot;`). This prevents the browser from interpreting injected content as code.

If dynamic HTML structure is needed in the future, HTML-escape the untrusted input explicitly before wrapping it in `Markup()`, or use other defense-in-depth measures such as a Content Security Policy.
