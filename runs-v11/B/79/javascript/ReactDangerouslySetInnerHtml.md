## Verdict

exploitable

## Source

`ticket.description` from API response at line 12 — untrusted external data returned unmodified from `/api/tickets/{ticketId}`

## Fix

**Vulnerable code:**
```javascript
<div dangerouslySetInnerHTML={{ __html: ticket.description }} />
```

**Fixed code:**
```javascript
import DOMPurify from 'dompurify';

// ... in component:
const sanitizedHTML = DOMPurify.sanitize(ticket.description);
return (
    <article className="ticket-detail">
        <h2>{ticket.subject}</h2>
        <p className="meta">Submitted by {ticket.submitterName}</p>
        <div dangerouslySetInnerHTML={{ __html: sanitizedHTML }} />
    </article>
);
```

## Explanation

The component renders a customer-supplied ticket description directly into the DOM via `dangerouslySetInnerHTML` without sanitization. An attacker can inject malicious HTML or JavaScript (e.g., `<img src=x onerror="alert('XSS')" />`) which executes in the victim's browser when the ticket is viewed. DOMPurify sanitizes the input by removing script tags, event handlers, and other dangerous elements while preserving safe HTML formatting. The sanitized output is assigned to a variable and used directly in the sink, preventing post-sanitization modifications from voiding the protection. Use DOMPurify version 3.4.0 or later (CVE-2026-41238 affects versions 3.0.1 through 3.3.3).

## Behaviour changes

- Import statement added: `import DOMPurify from 'dompurify'` — required dependency
- New variable `sanitizedHTML` introduces an intermediate step to hold the sanitized result before rendering — follows DOMPurify guidance against post-sanitization edits
- The rendered HTML content changes: malicious markup (script tags, event handlers, dangerous protocols) is removed while safe tags and attributes are preserved — this is the security fix and may alter display of unusual or intentionally complex markup in the description field

