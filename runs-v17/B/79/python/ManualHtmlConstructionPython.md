## Verdict

exploitable

## Source

**Lines 12-13**: Untrusted user input from query parameters `ticket` and `priority` via `request.args.get()`.

```
ticket_id = request.args.get("ticket", "")
priority = request.args.get("priority", "normal")
```

## Sink

**Line 28**: Return of unescaped HTML containing user input directly concatenated in string construction.

```
return page
```

The HTML string on lines 20-25 concatenates `ticket_id` and `priority` directly into HTML attributes without encoding:

```
page += "<p>Ticket: " + ticket_id + "</p>"
page += "<p>Priority: " + priority + "</p>"
```

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

    # SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
    return page
```

## Explanation

The vulnerability arises from manual HTML construction using string concatenation with untrusted user input without encoding. An attacker supplying `ticket_id` as `<img src=x onerror="alert('XSS')">` would have that injected directly into the HTML response, executing arbitrary JavaScript in the victim's browser.

The fix adds `import html` and wraps all dynamic values rendered into the HTML response with `html.escape()`, which converts special characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`). This ensures untrusted input is rendered as literal text rather than executable HTML/JavaScript, eliminating the XSS vector. The `html.escape()` function is part of Python's standard library and requires no external dependencies.

## Behaviour changes

**Lines 22-24 - Added `html.escape()` calls on three dynamic values:**
- `ticket_id`: User-controlled query parameter now safely escaped
- `priority`: User-controlled query parameter now safely escaped  
- `status`: Return value from `lookup_ticket_status()` also escaped for defense-in-depth (principle: encode at every output sink)

**Reason**: Context-aware HTML encoding is required to prevent injection. The original code rendered untrusted input into an HTML body context without encoding, which is the direct cause of the vulnerability. Special characters in user input (e.g., `<`, `>`) must be converted to their entity forms so the browser treats them as data, not markup.

No changes to function signature, control flow, return values, or other behavior. The application continues to work identically from a functional perspective, except that user input containing HTML metacharacters is now safely rendered as literal text instead of being parsed as HTML.

**Verification**: Syntax check with `python -m py_compile` passed. All function names (`html.escape`) are from Python's standard library `html` module (available in all Python 3.x versions). No external dependencies introduced.
