## Verdict

exploitable

## Source

HTTP request query parameters: `ticket_id` from `request.args.get("ticket", "")` (line 12) and `priority` from `request.args.get("priority", "normal")` (line 13). Both are attacker-controlled inputs with no validation.

## Fix

**Vulnerable code (lines 20-28):**
```python
page = "<html><body>"
page += "<h2>Support Ticket Lookup</h2>"
page += "<p>Ticket: " + ticket_id + "</p>"
page += "<p>Priority: " + priority + "</p>"
page += "<p>Status: " + status + "</p>"
page += "</body></html>"

return page
```

**Fixed code:**
```python
from html import escape

page = "<html><body>"
page += "<h2>Support Ticket Lookup</h2>"
page += "<p>Ticket: " + escape(ticket_id) + "</p>"
page += "<p>Priority: " + escape(priority) + "</p>"
page += "<p>Status: " + escape(status) + "</p>"
page += "</body></html>"

return page
```

## Explanation

The vulnerability occurs because `ticket_id` and `priority` are concatenated directly into an HTML string without encoding. An attacker can inject malicious HTML or JavaScript by providing payloads like `<img src=x onerror=alert()>` or `<script>alert()</script>` as query parameters. When this unencoded HTML is returned and rendered by the browser, the injected scripts execute with the privileges of the user's session.

The fix uses `html.escape()` from Python's standard library to convert special HTML characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`). This ensures that untrusted input remains data rather than executable code. The `status` variable returned by `lookup_ticket_status()` is also escaped as a defensive measure, though it appears to be static in this case.

## Behaviour changes

None. The `html.escape()` function only encodes special characters needed to prevent interpretation as HTML markup or attributes. Legitimate content containing `<`, `>`, `&`, or quotes will render correctly with their HTML entities displayed, which is the expected and safe behavior. The visual output remains identical for normal ticket IDs and priorities while preventing script injection.

