## Verdict
Confirmed. Line 28 returns HTML constructed from unescaped user input, permitting arbitrary script injection.

## Source
Lines 22–23 concatenate untrusted query parameters directly into the HTML string:
```python
page += "<p>Ticket: " + ticket_id + "</p>"
page += "<p>Priority: " + priority + "</p>"
```
Both `ticket_id` (from `request.args.get("ticket", "")` on line 12) and `priority` (from `request.args.get("priority", "normal")` on line 13) are attacker-controlled. An attacker passing `ticket=<script>alert('xss')</script>` causes arbitrary JavaScript to execute in the browser of anyone viewing the page.

## Fix
Import `escape` from `markupsafe` and apply it to both user-supplied values before concatenation:

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

Wrap each user-supplied variable in `escape()` before concatenating it into HTML. This converts HTML metacharacters (`<`, `>`, `&`, `"`, `'`) to their entity forms so they are rendered as text rather than parsed as markup or script.

## Explanation
The vulnerability arises because manual HTML string concatenation offers no protection against untrusted input. When a user's query parameter is directly inserted into the response, any HTML or JavaScript syntax they provide becomes part of the page structure. An attacker exploits this by injecting `<script>` tags or event handlers that execute in the victim's browser context with their session cookies and permissions.

Escaping (converting HTML metacharacters to `&lt;`, `&gt;`, `&amp;`, etc.) ensures that any injected syntax is rendered as literal text. `markupsafe.escape()` is Flask's built-in HTML escaping function and handles all dangerous characters. The fix also escapes `status` (line 24, now line 27 in the fixed version) defensively, even though it is derived from a trusted function; this follows defense-in-depth practice and protects against future changes to `lookup_ticket_status()` that might incorporate user data.
