## Verdict

- **CWE-79** (Improper Neutralization of Input During Web Page Generation - Cross-Site Scripting)
- **Location**: `ManualHtmlConstructionPython.py`, line 28 (sink reported by scanner) - root cause is the unescaped concatenation at lines 22-23
- **Verdict**: exploitable
- **Confidence**: high

## Source

- **Sources**: `request.args.get("ticket", "")` (line 12) and `request.args.get("priority", "normal")` (line 13) - Flask query-string parameters, fully attacker-controlled via the URL.
- **Data flow**: `ticket_id` and `priority` flow unmodified from the query string into a manually built HTML string (`page`) at lines 22-23 (`"<p>Ticket: " + ticket_id + "</p>"`, `"<p>Priority: " + priority + "</p>"`), with no validation or encoding applied anywhere in between. `status` (line 18) comes from `lookup_ticket_status(ticket_id)`, whose current stub implementation ignores its argument and always returns the constant `"Open"`, so it is not presently attacker-controlled, but it is concatenated into the same unescaped HTML string at line 24 and takes `ticket_id` as a parameter, so it is a latent injection point if that function is later implemented to reflect the input.
- **Sink**: the assembled `page` string is returned directly from the Flask view function at line 28. Flask serves a returned `str` with a default `Content-Type: text/html; charset=utf-8`, so the browser parses `page` as HTML/JS-executable markup. No template engine (and therefore no auto-escaping) is involved anywhere in this path - the string is built entirely with Python `+`/`+=` concatenation.
- **Sink contract** (established before fixing): the view returns a `str` (Flask wraps it in a `Response` with the default HTML content type); nothing is discarded; the status-code argument is implicit and defaults to `200` for the success path (an explicit `400` is already used for the empty-ticket case, which is unaffected by this fix); on `KeyError`/missing params, `request.args.get(...)` already defaults safely via its second argument, so there is no failure-behaviour dependency to preserve.
- Because no validation, escaping, or template auto-escaping occurs between the sources and the sink, the path is exploitable: a request such as `/ticket/status?ticket=<script>alert(1)</script>` renders the payload unescaped into the response body.

## Fix

No third-party library is required; Python's standard-library `html.escape()` is the guidance-recommended mechanism for encoding untrusted input in non-template, manually-constructed HTML.

Vulnerable code:

```python
from flask import Flask, request

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
    page += "<p>Ticket: " + ticket_id + "</p>"          # unescaped, attacker-controlled
    page += "<p>Priority: " + priority + "</p>"          # unescaped, attacker-controlled
    page += "<p>Status: " + status + "</p>"
    page += "</body></html>"

    # SAST FINDING: CWE-79 reported here. Sink is the next statement.
    return page
```

Fixed code:

```python
import html

from flask import Flask, request

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

    return page
```

## Explanation

The view builds its HTML response by string-concatenating `ticket_id` and `priority` - both taken directly from the query string - into the page body with no encoding, so any HTML/JavaScript in those parameters is returned verbatim and executes in the victim's browser. The fix wraps each value in `html.escape()` at the point it is written into the HTML string, converting `<`, `>`, `&`, `"`, and `'` into their HTML-entity equivalents so the data can no longer break out of the surrounding markup and be interpreted as tags or attributes. `status` is escaped too, as defense-in-depth: it is currently a hardcoded constant so this changes nothing about today's output, but it is derived from the tainted `ticket_id` parameter and would otherwise become a second injection point the moment `lookup_ticket_status` is implemented to reflect its input. No template engine or auto-escaping is available in this manual-string-building path, so `html.escape()` (rather than relying on framework defaults) is the correct primary defense here, applied at each output point rather than once on input.

## Behaviour changes

- `ticket_id`, `priority`, and `status` are now passed through `html.escape()` before being written into the response body. For any value containing `<`, `>`, `&`, `"`, or `'`, the returned HTML now shows the HTML-entity-encoded form instead of the raw characters - this is the intended effect of the fix, not a side effect of it.
- For all other inputs (no special characters), the escaped and unescaped output is byte-for-byte identical, including the current `status` value (`"Open"`), which `html.escape()` leaves unchanged.
- No change to status codes, return type, control flow, or the `Content-Type` Flask assigns to the response.
- Assumption: `status`'s current source (`lookup_ticket_status`) is a stub that ignores its input, so escaping it is precautionary rather than a fix for a presently-exploitable path through that value; confidence on the overall finding remains high since `ticket_id`/`priority` are directly and currently exploitable.
