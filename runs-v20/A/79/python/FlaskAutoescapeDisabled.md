## Verdict

Confirmed. The `label` query parameter is attacker-controlled, is explicitly marked as trusted HTML via `Markup(label)` (which suppresses Jinja2/markupsafe escaping instead of applying it), and is concatenated directly into the HTML response body that is returned to the client. A request such as `/tickets/status?label=<script>alert(1)</script>` reflects the payload unescaped into the page, resulting in stored-free reflected XSS.

## Source

`request.args.get("label", "Ticket")` in `ticket_status()` (`FlaskAutoescapeDisabled.py`, line 15) - an attacker-controlled query string parameter with no server-side allowlist or type constraint.

## Fix

### File: FlaskAutoescapeDisabled.py

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

    # The caller-supplied label is HTML-escaped before being placed next to
    # the status badge, so markup in the query string is rendered as inert
    # text rather than being interpreted by the browser.
    safe_label = escape(label)
    banner = f"<div class='ticket-banner'><span class='label'>{safe_label}</span>: {status}</div>"

    return f"<html><body>{banner}</body></html>"
```

## Explanation

The original code called `Markup(label)`, which does the opposite of escaping: it wraps the raw string in markupsafe's "already safe" marker so that no HTML entity encoding is ever applied to it, even though the string comes straight from `request.args`. When that value is then interpolated into an f-string and returned as the response body, any HTML or `<script>` content in `label` is emitted verbatim into the page and executed by the browser.

The fix replaces `Markup(label)` with `markupsafe.escape(label)`. `escape()` HTML-entity-encodes the five dangerous characters (`&`, `<`, `>`, `"`, `'`) and returns a `Markup` instance wrapping the *encoded* text, so it can still be dropped into an f-string (or a Jinja2 `{{ }}` context) without being re-escaped, but the characters that would let an attacker break out of the `<span>` element are neutralized. This preserves the existing response shape (plain HTML string built via f-strings, no template autoescaping involved) while closing the injection: `label=<script>alert(1)</script>` now renders as literal text (`&lt;script&gt;...`) instead of being parsed as markup.

No other behavior changes: `ticket_id` and `status` are not attacker-supplied free text in this snippet (the lookup is stubbed), so they are left as-is; only the sink that reflected unescaped `label` is addressed.
