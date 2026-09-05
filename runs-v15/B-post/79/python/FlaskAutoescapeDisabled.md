## Verdict

Exploitable. The untrusted `label` parameter from `request.args.get()` is wrapped with `Markup()` on line 20, which marks it as safe HTML and bypasses Jinja2 auto-escaping. This unsafe value flows directly into the HTML response on line 24, allowing arbitrary script injection.

## Source

**Data source:** `label = request.args.get("label", "Ticket")` (line 15) - untrusted user input from HTTP query parameters.

**Taint flow:** 
1. Untrusted `label` parameter from `request.args`
2. Wrapped with `Markup()` on line 20, marking it as safe despite being unvalidated
3. Embedded in f-string `banner` on line 21
4. Returned as raw HTML response on line 24

**Sink:** Line 24 `return f"<html><body>{banner}</body></html>"` - HTTP response body rendering.

## Fix

**Vulnerable code:**
```python
label = request.args.get("label", "Ticket")
status = lookup_ticket_status(ticket_id)

# The caller-supplied label is wrapped in Markup() so it can sit next to
# the status badge without Jinja2 escaping it when the page is rendered.
safe_label = Markup(label)
banner = f"<div class='ticket-banner'><span class='label'>{safe_label}</span>: {status}</div>"

# SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
return f"<html><body>{banner}</body></html>"
```

**Fixed code:**
```python
import html

label = request.args.get("label", "Ticket")
status = lookup_ticket_status(ticket_id)

# Properly escape the user-supplied label to prevent XSS
safe_label = html.escape(label)
banner = f"<div class='ticket-banner'><span class='label'>{safe_label}</span>: {status}</div>"

return f"<html><body>{banner}</body></html>"
```

## Explanation

The vulnerability stems from using `Markup()` to mark untrusted user input as safe HTML. This bypasses Flask's default auto-escaping and allows attacker-controlled content to be rendered as executable code. The fix replaces `Markup(label)` with `html.escape(label)`, which encodes HTML special characters (`<`, `>`, `&`, `"`, `'`) into their entity equivalents. This ensures the label is treated as text content, not HTML markup. The application's logic remains unchanged—the label still appears visually alongside the status badge—but injected scripts can no longer execute because angle brackets and other metacharacters are encoded. The `html.escape()` function is from Python's standard library and requires no external dependencies.

## Behaviour changes

None. The `html.escape()` function produces a string that is rendered as plain text within the HTML context, just as intended. Legitimate labels containing `<`, `>`, or `&` characters will now display their entity-encoded forms in the browser (e.g., `<test>` displays as `&lt;test&gt;`), which is the expected and secure behaviour for user-supplied text in HTML. The HTML structure of the banner and the status badge display remain unchanged.
