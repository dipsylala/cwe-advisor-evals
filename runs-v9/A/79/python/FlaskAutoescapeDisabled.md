## Verdict

Confirmed. Reflected XSS: the `label` query parameter is wrapped in `markupsafe.Markup()` before being interpolated into an HTML string that is returned directly as the response body. `Markup()` marks its argument as pre-escaped/safe-to-render HTML without performing any escaping itself, so any HTML or script markup in `label` is emitted into the page verbatim and executes in the victim's browser.

## Source

`request.args.get("label", "Ticket")` at line 15 in `ticket_status()` — an attacker-controlled query string parameter (e.g. `/tickets/status?label=<script>...</script>`).

## Fix

```python
from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)


def lookup_ticket_status(ticket_id):
    # Stubbed lookup for the purposes of this example.
    return "open"


@app.route("/tickets/status")
def ticket_status():
    ticket_id = request.args.get("ticket_id", "")
    label = request.args.get("label", "Ticket")
    status = lookup_ticket_status(ticket_id)

    # escape() HTML-encodes the caller-supplied label instead of asserting
    # (falsely) that it is already safe markup.
    safe_label = escape(label)
    banner = f"<div class='ticket-banner'><span class='label'>{safe_label}</span>: {status}</div>"

    return f"<html><body>{banner}</body></html>"
```

## Explanation

The root cause is the call to `Markup(label)` at line 20. `Markup` is `markupsafe`'s "this string is already safe HTML, do not escape it" wrapper — it is the inverse of an escaping function. Applying it to raw, attacker-controlled request data tells the templating/string layer to trust content that has never been sanitized, which is exactly what lets `<script>` or event-handler payloads in the `label` parameter reach the response unmodified.

The fix replaces `Markup(label)` with `escape(label)`, `markupsafe`'s HTML-escaping function. It encodes `<`, `>`, `&`, `'`, and `"` into their HTML entity equivalents, so any markup supplied in `label` renders as inert text inside the `<span class="label">` element instead of being parsed as HTML. The result of `escape()` is itself a `Markup` instance (already escaped), so it can still be interpolated directly into the f-string without being double-escaped.

No other input needs additional handling here: `ticket_id` is read but never echoed into the response, and `status` comes from the trusted server-side `lookup_ticket_status()` function rather than from request data. If a template engine is introduced for this response in the future, Flask's Jinja2 environment autoescapes by default for `.html`/`.htm`/`.xml` templates and `render_template_string`, so the safer general pattern is to render through Jinja2 with autoescaping left enabled rather than hand-building HTML strings, reserving `Markup()`/`escape(..., ...)` overrides for content that has been through an explicit, audited sanitizer.
