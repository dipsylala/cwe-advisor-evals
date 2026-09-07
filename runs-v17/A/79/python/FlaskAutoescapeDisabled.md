## Verdict

VULNERABLE - CWE-79 (Cross-site Scripting)

## Source

Line 20 marks untrusted user input with `Markup()`, disabling autoescaping. Line 24 embeds this unsafe data into the HTML response, allowing arbitrary script injection via the `label` query parameter.

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

    # Escape the user-supplied label to prevent XSS injection
    safe_label = html.escape(label)
    banner = f"<div class='ticket-banner'><span class='label'>{safe_label}</span>: {status}</div>"

    return f"<html><body>{banner}</body></html>"
```

## Explanation

The vulnerability stems from wrapping untrusted user input in `Markup()`, which disables escaping and allows HTML/JavaScript injection. The fix applies context-specific output encoding:

- Replace `Markup(label)` with `html.escape(label)` to encode the user-supplied label for HTML context
- `html.escape()` is the standard library's dependency-free alternative (recommended in the guidance; `markupsafe.Markup` exports from Flask are deprecated in 2.3.0+)
- The escaping preserves the HTML structure (`<div>`, `<span>` tags remain intact) while neutralizing injected scripts
- `status` comes from a stubbed function and does not require escaping for this code path

This follows the remediation principle: "Never mark untrusted input as safe" and "Apply context-specific encoding at each output sink."
