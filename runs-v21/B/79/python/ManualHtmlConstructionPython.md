## Verdict

The finding is real and exploitable. Untrusted query parameters (`ticket` and `priority`) are directly concatenated into HTML without encoding, allowing attackers to inject arbitrary HTML and JavaScript.

## Source

Line 12-13: Untrusted data from query parameters:
```python
ticket_id = request.args.get("ticket", "")
priority = request.args.get("priority", "normal")
```

Lines 22-24: Direct concatenation into HTML without encoding:
```python
page += "<p>Ticket: " + ticket_id + "</p>"
page += "<p>Priority: " + priority + "</p>"
page += "<p>Status: " + status + "</p>"
```

Line 28: The unencoded HTML is returned to the client.

## Fix

### File: ManualHtmlConstructionPython.py

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

The fix applies context-aware HTML encoding to all untrusted variables before they are concatenated into the response. The `html.escape()` function from Python's standard library converts special characters (`<`, `>`, `&`, `"`, and `'`) into their HTML entity equivalents, preventing the browser from interpreting them as HTML/JavaScript syntax. This is the primary defence mechanism recommended in the CWE-79 guidance for manual HTML construction.

The fix imports the `html` module (line 2) and applies `html.escape()` to `ticket_id`, `priority`, and `status` at lines 23, 24, and 25 respectively - the points where these values are rendered into HTML. With this encoding in place, an attacker cannot break out of the `<p>` tags or inject script elements, even if they craft payloads like `<script>alert('xss')</script>` or `"><script>`.

## Behaviour changes

- Legitimate HTML-like content in user input (e.g., `<` and `>` characters) will now be displayed as encoded entities (`&lt;`, `&gt;`) rather than as literal characters. This is the correct and intended behaviour for text content in HTML.
- Response payload size increases slightly due to entity encoding (e.g., `<` becomes `&lt;`), but this is negligible.
- No breaking changes to application logic or legitimate user workflows.
