## Verdict

exploitable

## Source

User-controlled input from request query parameters:
- Line 12: `ticket_id = request.args.get("ticket", "")` 
- Line 13: `priority = request.args.get("priority", "normal")`

Data flows to HTML output via string concatenation on lines 22-23 without encoding.

## Fix

**Vulnerable Code:**
```python
page = "<html><body>"
page += "<h2>Support Ticket Lookup</h2>"
page += "<p>Ticket: " + ticket_id + "</p>"
page += "<p>Priority: " + priority + "</p>"
page += "<p>Status: " + status + "</p>"
page += "</body></html>"
```

**Fixed Code:**
```python
import html

page = "<html><body>"
page += "<h2>Support Ticket Lookup</h2>"
page += "<p>Ticket: " + html.escape(ticket_id) + "</p>"
page += "<p>Priority: " + html.escape(priority) + "</p>"
page += "<p>Status: " + html.escape(status) + "</p>"
page += "</body></html>"
```

## Explanation

The vulnerability occurs because `ticket_id` and `priority` query parameters are concatenated directly into HTML output without encoding. An attacker can inject arbitrary HTML and JavaScript by supplying payloads like `<script>alert('xss')</script>` in the `ticket` parameter or `<img src=x onerror=alert(1)>` in the `priority` parameter, which will execute in the victim's browser.

The fix applies `html.escape()` from the Python standard library to both user-supplied variables before concatenation. This function encodes special HTML characters (`<` → `&lt;`, `>` → `&gt;`, `&` → `&amp;`, `"` → `&quot;`, `'` → `&#x27;`) so they render as text rather than executable markup. The `status` variable (from `lookup_ticket_status()`) is also escaped as a defence-in-depth measure, even though it originates from application code rather than user input.

## Behaviour changes

- Added `import html` at module level
- `ticket_id`, `priority`, and `status` variables are now escaped when rendered, so special HTML characters display as literal text instead of being interpreted as markup
- Legitimate content containing `<`, `>`, `&`, or quotes will display correctly with entities visible to the user (e.g., user input "Dept & Legal" renders as "Dept &amp; Legal")

Verification: Python syntax check passed with `python -m py_compile` on the fixed code. The `html.escape()` function is part of the Python 3 standard library (available since 3.2) with no external dependencies.

Assumptions: The Flask application is configured to return the response with an appropriate `Content-Type: text/html; charset=utf-8` header so character encoding is correctly interpreted by the browser. The application does not need rich HTML rendering (if it did, a sanitization library like `nh3` would be required instead).
