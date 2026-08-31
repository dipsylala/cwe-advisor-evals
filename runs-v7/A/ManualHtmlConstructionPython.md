## Verdict

Confirmed. User-supplied query parameters are concatenated directly into HTML output without escaping, enabling reflected XSS via the `ticket` and `priority` parameters.

## Source

Lines 12–13: Untrusted query parameters are extracted from the request.

Lines 22–23: These parameters are concatenated directly into HTML markup without sanitization.

Line 28: The unsanitized HTML is returned to the browser.

## Fix

```python
from flask import Flask, request, escape

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

## Explanation

The vulnerability exists because user-controlled query parameters are inserted into HTML without encoding special characters. An attacker can inject HTML or JavaScript by passing `<script>` tags or event handlers in the `ticket` or `priority` parameters.

Flask's `escape()` function (from `markupsafe`) converts dangerous characters like `<`, `>`, `&`, and `"` to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`), rendering them inert as text rather than executable markup. This must be applied to all user-supplied data before insertion into HTML context, including query parameters, form data, database values, or any untrusted source.

The `status` variable, returned from `lookup_ticket_status()`, should also be escaped as a defense-in-depth measure in case that function's implementation changes or accepts external input in the future.

