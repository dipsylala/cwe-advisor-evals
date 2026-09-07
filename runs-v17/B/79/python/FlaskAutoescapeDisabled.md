## Verdict

Confirmed: CWE-79 cross-site scripting vulnerability. The untrusted `label` parameter from user input is wrapped in `Markup()`, which disables HTML escaping and allows arbitrary HTML/JavaScript injection into the page output.

## Source

Line 14-15: `label = request.args.get("label", "Ticket")` — untrusted query parameter.

Line 20: `safe_label = Markup(label)` — vulnerability sink. The `Markup()` call from markupsafe marks the untrusted input as safe HTML, instructing the template engine to output it unescaped.

Line 24: `return f"<html><body>{banner}</body></html>"` — the unescaped label is returned to the browser in an HTML response.

**Attack vector**: An attacker can supply `?label=<script>alert('xss')</script>` and the script executes in the victim's browser.

## Fix

### File: FlaskAutoescapeDisabled.py

```python
from flask import Flask, request
import html

app = Flask(__name__)


def lookup_ticket_status(ticket_id):
    # Stubbed lookup for the purposes of this example.
    return "open"


@app.route("/tickets/status")
def ticket_status():
    ticket_id = request.args.get("ticket_id", "")
    label = request.args.get("label", "Ticket")
    status = lookup_ticket_status(ticket_id)

    # Escape the caller-supplied label to prevent XSS injection
    safe_label = html.escape(label)
    banner = f"<div class='ticket-banner'><span class='label'>{safe_label}</span>: {status}</div>"

    return f"<html><body>{banner}</body></html>"
```

## Explanation

The fix replaces `Markup(label)` with `html.escape(label)`. The standard library's `html.escape()` function converts HTML special characters (`<`, `>`, `&`, `"`, `'`) into their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), rendering them as literal text rather than executable markup. This prevents injected scripts and HTML tags from being interpreted by the browser.

The `Markup()` import from markupsafe is no longer needed and is removed. Import of `html` module from Python standard library is added (no external dependencies required).

This preserves the original functionality: the label still displays next to the status badge, but any special characters in user input are safely escaped.

## Behaviour changes

- **Input display**: User input containing `<`, `>`, `&`, quotes now displays with these characters escaped as HTML entities (e.g., `<script>` displays literally as `&lt;script&gt;`). This is the correct and expected behaviour for user input in HTML context.
- **No functional impact**: Legitimate text labels with no special characters display identically. The page structure and styling are unchanged.
- **XSS attack prevention**: The vulnerability is closed — injected scripts no longer execute.
