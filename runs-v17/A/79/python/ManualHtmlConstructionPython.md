## Verdict

CWE-79 (Cross-site Scripting) is confirmed. User-controlled input from `request.args.get()` on lines 12-13 (`ticket_id` and `priority`) flows directly into HTML string concatenation without escaping. When returned as an HTTP response on line 28, this allows injected script or event handlers to execute in the victim's browser.

## Source

The vulnerability originates at lines 12-13 where untrusted request parameters are extracted:
- `ticket_id = request.args.get("ticket", "")`
- `priority = request.args.get("priority", "normal")`

These values flow through lines 22-23 where they are concatenated directly into an HTML string without sanitization:
- `page += "<p>Ticket: " + ticket_id + "</p>"`
- `page += "<p>Priority: " + priority + "</p>"`

The sink is line 28 where the constructed HTML string is returned as the HTTP response.

An attacker can inject `ticket=<script>alert('xss')</script>` or `priority=<img src=x onerror="alert('xss')">` to execute arbitrary JavaScript.

## Fix

### File: ManualHtmlConstructionPython.py

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

    # SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
    return page
```

## Explanation

The fix applies HTML entity escaping to all variables included in the response using `escape()` from `markupsafe`, which is bundled with Flask. This converts dangerous characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), preventing the injected markup from being interpreted as HTML or JavaScript.

The escaping is applied on lines 22-24 to:
- `ticket_id` - user-controlled parameter
- `priority` - user-controlled parameter  
- `status` - return value from application logic (escaped for defense-in-depth)

This ensures that any special characters in user input are rendered as text content rather than executable code, eliminating the XSS attack surface.
