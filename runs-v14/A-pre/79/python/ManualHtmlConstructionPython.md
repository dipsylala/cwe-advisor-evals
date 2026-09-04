## Verdict

The code is vulnerable to reflected cross-site scripting (XSS). User-supplied query parameters `ticket` and `priority` are concatenated directly into HTML without escaping, allowing an attacker to inject arbitrary JavaScript that executes in the victim's browser.

## Source

The vulnerable data flow:
1. `ticket_id = request.args.get("ticket", "")` — untrusted user input from query string
2. `priority = request.args.get("priority", "normal")` — untrusted user input from query string
3. Lines 22-23: direct concatenation into HTML string: `"<p>Ticket: " + ticket_id + "</p>"` and `"<p>Priority: " + priority + "</p>"`
4. Line 28: HTML string returned in HTTP response without escaping

An attacker can craft a URL like `/ticket/status?ticket=<script>alert('xss')</script>&priority=high` to inject and execute JavaScript in the victim's browser.

## Fix

Replace manual HTML string construction with Jinja2 template rendering, which auto-escapes all variable output by default. Alternatively, use `markupsafe.escape()` to escape each variable before concatenation.

**Option 1 (Recommended): Use Jinja2 templates**

```python
from flask import Flask, request, render_string_template

app = Flask(__name__)

def lookup_ticket_status(ticket_id):
    return "Open"

@app.route("/ticket/status")
def ticket_status():
    ticket_id = request.args.get("ticket", "")
    priority = request.args.get("priority", "normal")

    if not ticket_id:
        return "<p>Please provide a ticket number.</p>", 400

    status = lookup_ticket_status(ticket_id)

    template = """
    <html><body>
    <h2>Support Ticket Lookup</h2>
    <p>Ticket: {{ ticket_id }}</p>
    <p>Priority: {{ priority }}</p>
    <p>Status: {{ status }}</p>
    </body></html>
    """
    return render_string_template(template, ticket_id=ticket_id, priority=priority, status=status)
```

Or use `render_template` with a separate template file.

**Option 2: Escape each variable**

```python
from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)

def lookup_ticket_status(ticket_id):
    return "Open"

@app.route("/ticket/status")
def ticket_status():
    ticket_id = request.args.get("ticket", "")
    priority = request.args.get("priority", "normal")

    if not ticket_id:
        return "<p>Please provide a ticket number.</p>", 400

    status = lookup_ticket_status(ticket_id)

    page = "<html><body>"
    page += "<h2>Support Ticket Lookup</h2>"
    page += "<p>Ticket: " + escape(ticket_id) + "</p>"
    page += "<p>Priority: " + escape(priority) + "</p>"
    page += "<p>Status: " + escape(status) + "</p>"
    page += "</body></html>"

    return page
```

The `escape()` function converts characters like `<`, `>`, `"`, and `&` into their HTML entity equivalents (`&lt;`, `&gt;`, `&quot;`, `&amp;`), preventing injected tags from being interpreted as HTML markup.

## Explanation

CWE-79 (Cross-Site Scripting) occurs when untrusted input is rendered into HTML without neutralization. The vulnerability allows attackers to:
- Steal session cookies and authentication tokens
- Redirect users to malicious sites
- Modify page content shown to the user
- Perform actions on behalf of the user

The fix works by ensuring that any special characters in user input are converted to their HTML entity equivalents before being placed into the response. This way, `<script>alert('xss')</script>` becomes `&lt;script&gt;alert('xss')&lt;/script&gt;`, which the browser displays as literal text rather than executing as code.

Jinja2 templates provide automatic context-aware escaping by default, making them the preferred approach. If manual string construction is necessary, `markupsafe.escape()` provides the required HTML entity encoding.
