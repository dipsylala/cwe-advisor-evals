## Verdict

Exploitable. `ticket_id` and `priority` are read unvalidated from `request.args` and concatenated directly into an HTML string returned as the Flask response body with no encoding, so a query string such as `?ticket=<script>alert(1)</script>` executes in the victim's browser.

## Source

`request.args.get("ticket", "")` and `request.args.get("priority", "normal")` in `ticket_status()` (lines 12-13) - both are attacker-controlled query-string parameters.

## Fix

CWE-79, Python: manual string concatenation into an HTML response with no template engine involved is a non-template context, so the applicable guidance is `Use html.escape() when rendering user input in non-template contexts` (`cwe/79/python/INDEX.md`). No third-party library is needed; `html.escape()` is in the Python standard library.

### File: ManualHtmlConstructionPython.py

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

`ticket_id` and `priority` are attacker-controlled query-string values concatenated verbatim into the HTML response, so any HTML metacharacters they contain (`<`, `>`, `&`, quotes) are interpreted as markup by the browser rather than displayed as text - the classic reflected-XSS shape. The fix wraps each tainted value in `html.escape()` at the point it is concatenated into `page`, converting `<`, `>`, `&`, `"`, and `'` into their HTML entity equivalents before they reach the response body. This is the correct layer for this sink because no template engine (Jinja2/Django) is in use here - the page is built as a plain Python string, so there is no auto-escaping to rely on or restore; `html.escape()` is the standard-library equivalent for that case. `status` is also wrapped for defence-in-depth even though the current stub returns a fixed literal, since `lookup_ticket_status()` returns a value rendered through the same sink and a future implementation reading from a database should not have to be revisited to add escaping later.

## Behaviour changes

- Added `import html` (standard library, no new dependency).
- `ticket_id`, `priority`, and `status` are now HTML-entity-encoded before being concatenated into the response body. For values containing no `<`, `>`, `&`, or quote characters (the common case for a ticket ID or a priority level like "normal"/"high"), the rendered output is byte-for-byte identical to before. For values containing those characters, the browser now displays them literally (e.g. `&lt;script&gt;`) instead of executing them - this is the intended effect of the fix, not an unrelated behaviour change.
- No arguments, return values, status codes, or control flow were altered; the 400 response for a missing `ticket_id` is unchanged.

Verification: `python -m py_compile` on the fixed file in a scratch location succeeded with no errors.
