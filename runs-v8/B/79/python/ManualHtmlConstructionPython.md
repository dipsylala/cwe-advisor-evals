## Verdict

Exploitable. Untrusted user input from `request.args.get()` is concatenated directly into HTML without escaping, allowing XSS injection.

## Source

- `ticket_id`: `request.args.get("ticket", "")` at line 12
- `priority`: `request.args.get("priority", "normal")` at line 13

Both variables are concatenated into HTML at lines 22-23 and returned unescaped at line 28.

## Fix

**Vulnerable Code (lines 20-28):**
```python
    page = "<html><body>"
    page += "<h2>Support Ticket Lookup</h2>"
    page += "<p>Ticket: " + ticket_id + "</p>"
    page += "<p>Priority: " + priority + "</p>"
    page += "<p>Status: " + status + "</p>"
    page += "</body></html>"

    return page
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

    return page
```

(Add `import html` at the top of the file with other imports.)

## Explanation

`html.escape()` converts HTML metacharacters (`<`, `>`, `&`, `"`, `'`) to entity references (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`). This ensures that user-supplied content is treated as data, not executable code. An attacker's payload like `<script>alert('XSS')</script>` becomes `&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;`, which the browser renders as literal text rather than executing as code. The fix applies context-aware output encoding at each sink (all three user-influenced fields are escaped before rendering).

## Behaviour changes

None. `html.escape()` preserves the semantic meaning of the data while neutralizing the injection vector. Legitimate content containing HTML metacharacters (e.g., "Price < $100") will be displayed correctly as escaped text, which is the expected behavior for HTML content context.
