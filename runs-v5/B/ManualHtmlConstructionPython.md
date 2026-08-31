## Verdict

exploitable (confidence: high)

- cwe_id: CWE-79
- location: ManualHtmlConstructionPython.py, line 28 (sink); line 22-23 (concatenation)

## Source

`request.args.get("ticket", "")` (line 12) and `request.args.get("priority", "normal")` (line 13) - both are Flask query-string parameters, fully attacker-controlled with no server-side default overriding an attacker-supplied value.

`status` (line 18, from `lookup_ticket_status(ticket_id)`) is not an XSS source in this file: the stub implementation returns the constant string `"Open"` regardless of input, so no attacker-controlled data flows through it here. It is left unescaped in the fix below on that basis - if `lookup_ticket_status` is later backed by a database or otherwise starts returning derived/attacker-influenced content, it becomes a source and needs the same treatment.

Data flow: `request.args` -> `ticket_id` / `priority` -> string-concatenated directly into `page` (lines 22-23) -> returned as the Flask response body (line 28), which Flask serves with `Content-Type: text/html` by default. No template engine and no auto-escaping is involved - `page` is a plain Python string built with `+=`, so nothing neutralizes HTML metacharacters before the browser parses the response.

## Fix

Vulnerable code:

```python
    page = "<html><body>"
    page += "<h2>Support Ticket Lookup</h2>"
    page += "<p>Ticket: " + ticket_id + "</p>"
    page += "<p>Priority: " + priority + "</p>"
    page += "<p>Status: " + status + "</p>"
    page += "</body></html>"

    # SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
    return page
```

Fixed code:

```python
    import html

    page = "<html><body>"
    page += "<h2>Support Ticket Lookup</h2>"
    page += "<p>Ticket: " + html.escape(ticket_id) + "</p>"
    page += "<p>Priority: " + html.escape(priority) + "</p>"
    page += "<p>Status: " + status + "</p>"
    page += "</body></html>"

    return page
```

(`import html` belongs at module scope alongside the existing `from flask import Flask, request` line in the real file; it is shown inline above only to keep the diff self-contained.)

## Explanation

`ticket_id` and `priority` come straight from the query string and were concatenated into the response body with no encoding, so a request such as `/ticket/status?ticket=<script>alert(1)</script>` reflects the payload verbatim into the HTML and executes in the victim's browser. Wrapping each value in `html.escape()` converts `<`, `>`, `&`, `'`, and `"` to their HTML entity equivalents before concatenation, so the browser renders the input as inert text inside the `<p>` element instead of parsing it as markup. This is the manual-encoding path from the Python guidance (`html.escape()` for non-template contexts) rather than the Flask auto-escaping path, because this handler builds the response as a plain string instead of rendering a Jinja2 template.

## Behaviour changes

- `ticket_id` and `priority` are now HTML-entity-encoded in the response body instead of appearing verbatim. A ticket number or priority value that legitimately contains `<`, `>`, `&`, or quote characters will now render as the literal characters (e.g. `&lt;`) rather than being interpreted as markup - this is the intended effect of the fix, not a side effect, and matches how any HTML-embedded text should display those characters.
- `status` is unchanged (still concatenated unescaped) since it is not attacker-controlled in the current implementation - see Source.
- Removed the `# SAST FINDING` comment marking the sink, since the finding is resolved at that line; no other comments, control flow, status codes, or return values were altered.
