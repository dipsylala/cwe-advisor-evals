## Verdict

**CONFIRMED**: The vulnerability is real and exploitable. User-supplied `ticket_id` and `priority` query parameters are directly concatenated into HTML without escaping, allowing arbitrary script injection.

## Source

Lines 22–23 reflect untrusted input from `request.args.get()` directly into the HTML response:
```
page += "<p>Ticket: " + ticket_id + "</p>"
page += "<p>Priority: " + priority + "</p>"
```

An attacker can inject `<script>` or event handler markup via `?ticket=<script>alert('xss')</script>` or `?priority='" onload="alert('xss')"` to execute arbitrary JavaScript in the victim's browser.

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

The fix applies `escape()` from `markupsafe` (imported directly, as Flask provides it) to each user-controlled value before embedding it into HTML. `escape()` converts special HTML characters (`<`, `>`, `"`, `'`, `&`) to their entity equivalents (`&lt;`, `&gt;`, `&quot;`, `&#x27;`, `&amp;`), ensuring that attacker-injected markup is rendered as literal text rather than executed as code.

The same escaping is applied to `status` for consistency and defense-in-depth, even though it is not directly user-supplied in this case.

This approach preserves the existing manual HTML construction pattern while eliminating the injection vector.
