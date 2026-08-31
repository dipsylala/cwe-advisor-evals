## Verdict

Exploitable. Both `ticket_id` and `priority` are attacker-controlled via HTTP query parameters and concatenated directly into HTML output without encoding. An attacker can inject arbitrary HTML/JavaScript through either parameter.

## Source

- Line 12: `ticket_id = request.args.get("ticket", "")` — attacker-controlled query parameter
- Line 13: `priority = request.args.get("priority", "normal")` — attacker-controlled query parameter
- Line 18: `status = lookup_ticket_status(ticket_id)` — dependent on `ticket_id` from line 12

## Fix

**Vulnerable code:**
```python
    status = lookup_ticket_status(ticket_id)

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
    import html
    
    status = lookup_ticket_status(ticket_id)

    # Escape untrusted input for safe HTML rendering
    ticket_id_escaped = html.escape(ticket_id)
    priority_escaped = html.escape(priority)
    status_escaped = html.escape(status)

    page = "<html><body>"
    page += "<h2>Support Ticket Lookup</h2>"
    page += "<p>Ticket: " + ticket_id_escaped + "</p>"
    page += "<p>Priority: " + priority_escaped + "</p>"
    page += "<p>Status: " + status_escaped + "</p>"
    page += "</body></html>"

    return page
```

## Explanation

The fix applies HTML entity encoding to all untrusted input values before they are concatenated into the HTML response. `html.escape()` converts special characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), ensuring that attacker-supplied payloads are rendered as text content rather than executable code. This transformation is applied at each sink (the concatenation points), not on input, because the same value might be rendered into different contexts requiring different encoding schemes. The `status` value is also escaped, since it is derived from user-controlled input (`ticket_id` parameter passed to `lookup_ticket_status()`), and defensive practices require treating all values that touch external context as requiring encoding until proven otherwise.

## Behaviour changes

The fix introduces an `import html` statement at the module level. All three HTML-injected values are now passed through `html.escape()` before use, which alters their string content by replacing special characters with entity representations. These entities are properly decoded by browsers in HTML body context, so legitimate content containing `<`, `&`, or quotes will display correctly. The HTTP response status codes remain unchanged (200 for success, 400 for missing ticket), and the response headers and content-type are unaffected.
