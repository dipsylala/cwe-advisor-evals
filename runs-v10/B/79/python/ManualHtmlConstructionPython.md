## Verdict
Exploitable. The application constructs HTML by concatenating unsanitized query parameters directly into a response string without any encoding or escaping, allowing an attacker to inject arbitrary JavaScript.

## Source
- `ticket_id` from `request.args.get("ticket", "")` at line 12
- `priority` from `request.args.get("priority", "normal")` at line 13
- `status` derived from `lookup_ticket_status(ticket_id)` at line 18, treated as potentially untrusted output

## Fix
**Vulnerable code (lines 1-28):**
```python
from flask import Flask, request

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
    page += "<p>Ticket: " + ticket_id + "</p>"
    page += "<p>Priority: " + priority + "</p>"
    page += "<p>Status: " + status + "</p>"
    page += "</body></html>"

    return page
```

**Fixed code:**
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
The fix imports the built-in `html` module and applies `html.escape()` to each untrusted value before concatenating it into the HTML string. The `html.escape()` function encodes special characters (`&`, `<`, `>`, `"`, `'`) to their HTML entity equivalents (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&#x27;`), preventing injected markup and scripts from being interpreted as code. This encoding is applied at the point where each value enters the HTML output, ensuring that user-supplied query parameters and database-derived values cannot break out of their text content context. The fix preserves the application's logic and return contract while eliminating the XSS vector.

## Behaviour changes
None. The `html.escape()` function returns a string with special characters encoded; this encoding is transparent to Flask's response handling and produces the same rendering in browsers. Legitimate content containing `<`, `&`, and quotes will be displayed as text rather than interpreted as markup, which is the intended and safe behavior.
