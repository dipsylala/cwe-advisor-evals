## Verdict

exploitable

## Source

Untrusted HTTP query parameters `ticket` and `priority` sourced from `request.args.get()` at lines 12-13 flow directly into HTML string concatenation at lines 22-23 without encoding.

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
import html
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
    page += "<p>Ticket: " + html.escape(ticket_id) + "</p>"
    page += "<p>Priority: " + html.escape(priority) + "</p>"
    page += "<p>Status: " + html.escape(status) + "</p>"
    page += "</body></html>"

    return page
```

## Explanation

The fix adds `import html` and wraps all untrusted values (`ticket_id`, `priority`, and `status`) with `html.escape()` before concatenation. `html.escape()` encodes special HTML characters (`<`, `>`, `&`, `"`) as HTML entities, preventing injected markup and scripts from executing in the browser. The function is part of Python's standard library with no external dependency required. Legitimate text containing these characters is preserved correctly — a ticket named "Q&A" becomes "Q&amp;A" in the HTML, displaying as "Q&A" in the browser.

## Behaviour changes

None. `html.escape()` leaves all alphanumeric and most punctuation unchanged; only characters with special meaning in HTML context (`<`, `>`, `&`, `"`) are encoded. The rendered page displays identically to the unfixed version for benign input, but rejects malicious payloads.
