## Verdict

Confirmed XSS vulnerability via `dangerouslySetInnerHTML`.

## Source

Line 24: `ticket.description` originates from an untrusted API response (`/api/tickets/{ticketId}`) that returns customer-supplied free-text input unmodified (lines 10-12). The API caller has no control over what the customer typed in the "Describe your issue" field.

## Fix

Replace `dangerouslySetInnerHTML` with standard React text content rendering, which escapes HTML metacharacters:

```javascript
<div className="ticket-description">{ticket.description}</div>
```

## Explanation

`dangerouslySetInnerHTML` bypasses React's default escaping and renders its argument as raw HTML. When the argument comes from untrusted input—here, unvalidated customer text—an attacker can inject script tags or event handlers (e.g., `<img src=x onerror="alert('xss')">`), which execute in the victim's browser with the session cookie and CSRF token.

React's default text rendering automatically escapes HTML metacharacters (`<`, `>`, `&`, `"`, `'`), so malicious markup becomes visible text rather than executable code. This preserves customer formatting that was plain text (line breaks, special characters) while blocking code injection.

If rich HTML formatting from customers is intended, use a sanitization library like `DOMPurify` with a strict whitelist (e.g., allow `<b>`, `<i>`, `<br>` only; reject `<script>`, `<iframe>`, event handlers). In this case, the requirement is not stated, and the default safe behavior is appropriate.
