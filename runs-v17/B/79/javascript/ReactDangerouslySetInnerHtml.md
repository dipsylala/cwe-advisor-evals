## Verdict

The finding is **confirmed**. Untrusted user input (`ticket.description` from an external API) flows directly into the `dangerouslySetInnerHTML` sink at line 24 without sanitization, creating an exploitable stored XSS vulnerability. An attacker can inject malicious scripts through the ticket description field that execute in the browsers of customers viewing the ticket.

## Source

The `ticket.description` field originates from the API response at `/api/tickets/{ticketId}` (line 10-12). The API comment states it returns the user-supplied text unmodified, making it untrusted. This value is customer-supplied free-text that an attacker can control.

## Fix

Add DOMPurify sanitization before rendering. The fix requires:

1. **Dependency**: Add `dompurify` (minimum version 3.4.0) to your `package.json`
2. **Code change**: Import DOMPurify, sanitize the description, and pass only the sanitized result to `dangerouslySetInnerHTML`

### File: ReactDangerouslySetInnerHtml.js

```javascript
import React, { useEffect, useState } from 'react';
import DOMPurify from 'dompurify';

// Renders a customer support ticket, including the free-text description
// the customer typed into the "Describe your issue" field when they
// submitted the ticket. The API returns that text unmodified.
function TicketDetail({ ticketId }) {
    const [ticket, setTicket] = useState(null);

    useEffect(() => {
        fetch(`/api/tickets/${ticketId}`)
            .then((res) => res.json())
            .then((data) => setTicket(data));
    }, [ticketId]);

    if (!ticket) {
        return <p>Loading ticket...</p>;
    }

    const sanitizedDescription = DOMPurify.sanitize(ticket.description);

    return (
        <article className="ticket-detail">
            <h2>{ticket.subject}</h2>
            <p className="meta">Submitted by {ticket.submitterName}</p>
            <div dangerouslySetInnerHTML={{ __html: sanitizedDescription }} />
        </article>
    );
}

export default TicketDetail;
```

## Explanation

DOMPurify removes script tags, event handlers (`onclick`, `onerror`, etc.), and other dangerous markup while preserving safe HTML elements. By calling `DOMPurify.sanitize(ticket.description)` before passing it to `dangerouslySetInnerHTML`, the sanitized output is guaranteed to contain no executable code.

The fixed code creates a new variable `sanitizedDescription` and assigns only the return value of `DOMPurify.sanitize()` to it, then passes that trusted value to the sink. This prevents the original tainted input from being rendered.

Version floor: DOMPurify 3.4.0 or later closes CVE-2026-41238, which affected earlier versions under the plain `sanitize(input)` call with no special configuration.

## Behaviour changes

- **Added dependency**: DOMPurify must be installed and available at runtime
- **HTML filtering**: Any `<script>` tags, event handlers, or other dangerous markup in `ticket.description` will be removed during sanitization. Safe HTML formatting (headings, paragraphs, links, bold, italics, etc.) is preserved
- **Performance**: Sanitization happens on each render when ticket data updates; for high-volume rendering, consider memoizing the result
- **Output format**: The rendered HTML may differ from the original if it contained injected code; legitimate formatted text remains intact
