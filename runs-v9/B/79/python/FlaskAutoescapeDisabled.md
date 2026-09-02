## Verdict

- **CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation - Cross-Site Scripting)
- **Location**: `FlaskAutoescapeDisabled.py`, line 24 (sink), with the root cause at line 20
- **Verdict**: exploitable
- **Confidence**: high
- **Assumptions**: The finding title references "autoescape disabled," but the route never calls `render_template`/`render_template_string`, so no Jinja2 autoescape setting is in play here. The exploitable mechanism is the direct use of `Markup()` on unsanitized user input inside manually built HTML strings; treated the reported line as the terminal sink for that flow.

## Source

- **Source**: `request.args.get("label", "Ticket")` at line 15 - the `label` query parameter, fully attacker-controlled.
- **Flow**: `label` is passed unmodified into `Markup(label)` at line 20. `Markup()` does not escape its argument; it only marks the string as "already safe HTML," so any `<script>`, `<img onerror=...>`, or similar payload in `label` passes through unchanged. `safe_label` is then interpolated into `banner` via an f-string at line 21, and `banner` is interpolated into the final HTML document at line 24.
- **Sink**: the f-string at line 24 (`return f"<html><body>{banner}</body></html>"`). Flask returns this string as the HTTP response body with `Content-Type: text/html`, so any unescaped markup in it executes in the victim's browser.
- **Sink contract**: the view function returns a `str`; Flask wraps it in a 200 `text/html` response. No headers are set explicitly, no output is discarded, and there is no error path to preserve - the fix only needs to change what content reaches that return.

## Fix

Vulnerable code:

```python
from flask import Flask, request
from markupsafe import Markup

app = Flask(__name__)


def lookup_ticket_status(ticket_id):
    # Stubbed lookup for the purposes of this example.
    return "open"


@app.route("/tickets/status")
def ticket_status():
    ticket_id = request.args.get("ticket_id", "")
    label = request.args.get("label", "Ticket")
    status = lookup_ticket_status(ticket_id)

    # The caller-supplied label is wrapped in Markup() so it can sit next to
    # the status badge without Jinja2 escaping it when the page is rendered.
    safe_label = Markup(label)  # VULNERABLE: marks untrusted input as safe HTML without encoding it
    banner = f"<div class='ticket-banner'><span class='label'>{safe_label}</span>: {status}</div>"

    return f"<html><body>{banner}</body></html>"
```

Fixed code:

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

    # HTML-encode the caller-supplied label before it is placed in the response.
    safe_label = escape(label)
    banner = f"<div class='ticket-banner'><span class='label'>{safe_label}</span>: {status}</div>"

    return f"<html><body>{banner}</body></html>"
```

## Explanation

`Markup(label)` does not encode its argument - it only asserts that the wrapped string is already safe HTML, so wrapping attacker-controlled `label` in it was a no-op for security while looking like a safety measure. Replacing it with `markupsafe.escape(label)` HTML-encodes the five characters that let a value break out of HTML body/attribute context (`&`, `<`, `>`, `"`, `'`) and returns a `Markup` instance, so `safe_label` still composes correctly inside the surrounding f-strings without re-escaping. This closes the injection at the point the untrusted value enters the markup, which is the pattern this codebase's own knowledge base calls for: never mark untrusted input safe, and encode at the output sink rather than trusting an upstream framework setting that isn't even active on this code path (no `render_template`/Jinja2 rendering occurs here).

## Behaviour changes

- For any `label` value containing `& < > " '`, the response body now shows the HTML-encoded entities (e.g. `&lt;script&gt;`) instead of the literal characters/markup - this is the intended effect of the fix and is what stops the injected markup from executing.
- For a `label` value containing none of those characters (the common case, e.g. the default `"Ticket"`), the rendered output is byte-for-byte identical to before.
- No change to the response status code, `Content-Type`, headers, or the `status`/`ticket_id` handling - only the encoding applied to `label` changed.
