## Verdict

exploitable (confidence: high)

CWE-79 - Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting'), in `FlaskAutoescapeDisabled.py`, line 24.

## Source

`request.args.get("label", "Ticket")` at line 15 - the `label` query-string parameter, fully attacker-controlled.

(`ticket_id`, taken from `request.args.get("ticket_id", "")` at line 14, is also unvalidated but is not part of the exploitable path here: `lookup_ticket_status()` ignores its argument and always returns the constant `"open"`, so `status` carries no attacker-controlled content in this file.)

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
    safe_label = Markup(label)
    banner = f"<div class='ticket-banner'><span class='label'>{safe_label}</span>: {status}</div>"

    # SAST FINDING: CWE-79 reported here. Sink is the next statement.
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

    # Escape the caller-supplied label before it is placed in the HTML response.
    safe_label = escape(label)
    banner = f"<div class='ticket-banner'><span class='label'>{safe_label}</span>: {status}</div>"

    return f"<html><body>{banner}</body></html>"
```

## Explanation

This handler never goes through Jinja2 rendering - it builds the response HTML directly with nested f-strings and returns the resulting string as the view's return value, so template auto-escaping is not the relevant control here. The vulnerability is that `label` is wrapped in `markupsafe.Markup()` at line 20, which does not encode the string - it only tags it as "already safe HTML" - and an f-string interpolation calls `str()` on that value, not `__html__()`, so the tag has no runtime effect either way: the raw, attacker-supplied bytes reach the response body unescaped at line 24, the reported sink. A request such as `?label=<script>alert(1)</script>` renders and executes in the victim's browser.

The fix replaces `Markup(label)` with `markupsafe.escape(label)`, which HTML-encodes `<`, `>`, `&`, `'`, and `"` and returns a `Markup`-typed, now-safe string. Swapping `Markup` for `escape` in the import keeps the fix to the one import plus the one line that performs the encoding; everything else - the f-string structure, the response shape, the unrelated `status`/`ticket_id` handling - is unchanged, consistent with `cwe/79/python/INDEX.md`'s guidance to use `html.escape()`/`markupsafe.escape()` for user input rendered outside of template auto-escaping, and never to mark untrusted input safe via `Markup()`.

## Behaviour changes

None to the response contract: the view still returns an HTML string built the same way, with the same status code and content type, and legitimate labels containing no special characters render identically to before. The only externally visible change is that a label containing `<`, `>`, `&`, `'`, or `"` now appears in the page as its HTML-encoded form (e.g. `&lt;b&gt;` instead of a literal `<b>`) rather than being interpreted as markup - which is the intended effect of closing the injection.

Assumption: `ticket_id` was traced and found non-exploitable in this file only because the stub `lookup_ticket_status()` discards its argument; no fix was applied to that parameter since it does not reach the sink, but a real implementation of `lookup_ticket_status()` that echoes `ticket_id` into `status` would need the same encoding treatment.
