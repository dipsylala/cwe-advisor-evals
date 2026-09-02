## Verdict

Confirmed. Lines 22-24 concatenate unsanitized user input directly into HTML output without escaping. The `ticket_id` and `priority` parameters from the query string are embedded as-is into the response, enabling an attacker to inject arbitrary HTML and JavaScript.

## Source

User input acquired via `request.args.get("ticket", "")` on line 12 and `request.args.get("priority", "normal")` on line 13 flows directly into HTML construction.

## Fix

Import `html` module and escape user input before concatenation:

```python
from flask import Flask, request
import html

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
    page += "<p>Ticket: " + html.escape(ticket_id) + "</p>"
    page += "<p>Priority: " + html.escape(priority) + "</p>"
    page += "<p>Status: " + html.escape(status) + "</p>"
    page += "</body></html>"

    return page
```

## Explanation

Direct string concatenation of unsanitized request parameters into HTML enables XSS. The Python `html.escape()` function (standard library, available in Python 3.2+) converts dangerous characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), which render as text rather than markup or script. This prevents injected tags and JavaScript from executing while preserving the intended display of user input.
