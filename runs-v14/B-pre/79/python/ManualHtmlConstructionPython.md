## Verdict
exploitable

## Source
The vulnerability originates from untrusted query parameters captured at lines 12-13:
- `ticket_id = request.args.get("ticket", "")` 
- `priority = request.args.get("priority", "normal")`

Both values flow directly into HTML concatenation at lines 22-23 without encoding:
- `page += "<p>Ticket: " + ticket_id + "</p>"`
- `page += "<p>Priority: " + priority + "</p>"`

The unescaped HTML string is then returned to the browser at line 28, allowing arbitrary HTML/JavaScript injection.

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
The fix applies context-aware HTML encoding to all untrusted data before concatenation into the HTML string. The built-in `html.escape()` function converts special characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), ensuring that attacker-controlled input is always treated as data, not executable markup or code. This prevents script injection: a payload like `<script>alert('XSS')</script>` becomes `&lt;script&gt;alert('XSS')&lt;/script&gt;`, which renders as plain text in the browser instead of executing.

## Behaviour changes
None. The escaping preserves the intended behavior—displaying the query parameters in the HTML response—while preventing code execution. Legitimate content containing angle brackets, ampersands, or quotes will display correctly as HTML entities rather than being interpreted as markup.
