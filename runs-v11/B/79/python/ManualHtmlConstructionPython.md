## Verdict

VULNERABLE — Direct concatenation of user-controlled input into HTML response without encoding.

## Source

Line 12-13: `ticket_id` and `priority` are untrusted data from `request.args.get()`, which reads the query string directly from the HTTP request.

## Fix

Import `html` module and apply `html.escape()` to all user-controlled values before HTML concatenation:

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

The vulnerability exists because user input from query parameters is concatenated directly into the HTML response without encoding. An attacker can inject payloads like `?ticket=<script>alert('XSS')</script>` which will be executed in the victim's browser.

The fix applies `html.escape()` to all three data values before insertion into HTML (`ticket_id`, `priority`, and `status`). This function converts special HTML characters to their entity equivalents: `<` becomes `&lt;`, `>` becomes `&gt;`, `&` becomes `&amp;`, and quotes become `&#x27;` or `&quot;`. This ensures the input is treated as text data rather than executable code.

## Behaviour changes

- User input containing HTML/script characters (e.g., `<`, `>`, `&`, quotes) will be displayed as literal text with entities visible in the HTML source, but rendered correctly in the browser
- An attacker's payload like `<script>alert('xss')</script>` will be displayed as the text string `<script>alert('xss')</script>` instead of executing
- Legitimate tickets with special characters in their IDs or priorities will render correctly without breaking the HTML structure
- The response remains an HTML document served as `text/html` with proper character encoding
