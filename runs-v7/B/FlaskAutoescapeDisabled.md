## Verdict

The finding is valid. Line 20 uses `Markup(label)` to mark untrusted user input as safe HTML, which disables escaping and directly creates a Cross-Site Scripting vulnerability. An attacker can inject malicious scripts through the `label` query parameter that will execute in victims' browsers.

## Source

Line 15: `label = request.args.get("label", "Ticket")` - untrusted user-controlled input from the HTTP query string.

## Fix

Replace the `Markup()` call with `html.escape()` to properly encode untrusted input before including it in HTML:

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

    # The caller-supplied label is properly escaped before inclusion in HTML
    safe_label = html.escape(label)
    banner = f"<div class='ticket-banner'><span class='label'>{safe_label}</span>: {status}</div>"

    return f"<html><body>{banner}</body></html>"
```

## Explanation

The original code used `Markup(label)` to mark untrusted user input as safe, explicitly disabling HTML escaping. This allows attackers to inject arbitrary HTML and JavaScript through the `label` query parameter. The fix replaces `Markup()` with `html.escape()`, which encodes dangerous characters (`<`, `>`, `&`, `"`, `'`) so they render as text rather than executable code. The escaped value is then safe to include in the HTML response without creating an XSS vector.

## Behaviour changes

- Payloads like `<script>alert('XSS')</script>` now render as text: `&lt;script&gt;alert('XSS')&lt;/script&gt;`
- Special characters in legitimate labels (`&`, `<`, `>`, quotes) are HTML-encoded and display correctly
- HTML markup in user-supplied labels is no longer executed - it is displayed as literal text
