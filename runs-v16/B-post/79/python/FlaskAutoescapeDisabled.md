## Verdict

Exploitable. Confidence: High.

The vulnerability allows arbitrary JavaScript injection through the `label` query parameter. An attacker can craft a request like `?label=<img onerror="alert('XSS')">` to execute code in victims' browsers.

## Source

`request.args.get("label", "")` at line 15 receives untrusted user input from the query string.

## Fix

**Vulnerable code (line 20, and line 21 construction):**
```python
safe_label = Markup(label)
banner = f"<div class='ticket-banner'><span class='label'>{safe_label}</span>: {status}</div>"
```

**Fixed code:**
```python
import html

# ... in the route function:
safe_label = html.escape(label)
safe_status = html.escape(status)
banner = f"<div class='ticket-banner'><span class='label'>{safe_label}</span>: {safe_status}</div>"
```

The complete fixed function:
```python
from flask import Flask, request
import html

app = Flask(__name__)

def lookup_ticket_status(ticket_id):
    return "open"

@app.route("/tickets/status")
def ticket_status():
    ticket_id = request.args.get("ticket_id", "")
    label = request.args.get("label", "Ticket")
    status = lookup_ticket_status(ticket_id)

    safe_label = html.escape(label)
    safe_status = html.escape(status)
    banner = f"<div class='ticket-banner'><span class='label'>{safe_label}</span>: {safe_status}</div>"

    return f"<html><body>{banner}</body></html>"
```

## Explanation

The `Markup()` wrapper was an explicit instruction to Flask/Jinja2 to treat the string as safe HTML and skip escaping. This bypassed all output encoding, allowing an attacker to inject arbitrary HTML and JavaScript. The fix replaces `Markup(label)` with `html.escape(label)`, which encodes HTML metacharacters (`<`, `>`, `&`, `"`) to entity references, preventing the browser from interpreting them as code. Additionally, `status` is escaped as well for defense-in-depth, since it comes from a function and should not be trusted. The `html` module is Python's standard library and requires no external dependencies.

## Behaviour changes

1. **Import change**: `from markupsafe import Markup` replaced with `import html`. The `markupsafe` module is no longer used. This is a dependency reduction with no functional impact.
2. **Output encoding**: HTML metacharacters in `label` and `status` are now encoded to entity references (e.g., `<` becomes `&lt;`, `>` becomes `&gt;`). Legitimate content containing these characters (e.g., "5 < 10", URLs with query strings) will display correctly as entity references rather than as HTML syntax. This is the intended security behaviour.
3. **No changes to the function signature, return type, or response format**: The function still returns an HTML string that Flask renders as a response; the content is simply escaped for safety.
