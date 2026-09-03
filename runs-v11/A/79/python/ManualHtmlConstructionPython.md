## Verdict
True Positive — CWE-79 (Improper Neutralization of Input During Web Page Generation)

## Source
File: `ManualHtmlConstructionPython.py`, lines 12-23

User-supplied request parameters (`ticket_id` from line 12 and `priority` from line 13) are concatenated directly into an HTML string on lines 22-23 without any escaping or sanitization. These values are then returned as HTML on line 28, allowing an attacker to inject arbitrary JavaScript or HTML by supplying malicious values in the query parameters.

## Fix
Import `escape` from `markupsafe` and apply it to all user-controlled input values before concatenating them into the HTML response:

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

## Explanation
The vulnerability arises from manual HTML construction without output encoding. User inputs must be escaped before inclusion in HTML to neutralize special characters (`<`, `>`, `&`, `"`, `'`) that have syntactic meaning in markup.

`markupsafe.escape()` converts these characters to HTML entity equivalents (`&lt;`, `&gt;`, etc.), preventing the browser from interpreting user input as code. While Flask has built-in access to this function, it is most commonly used via Jinja2 templates (which auto-escape by default), the most robust solution would be to move to template-based rendering. However, when manual HTML construction is necessary, explicit escaping of all user-controlled data before concatenation is required.

The `status` value from `lookup_ticket_status()` should also be escaped to follow defense-in-depth practices, since functions can evolve to return user-influenced data.
