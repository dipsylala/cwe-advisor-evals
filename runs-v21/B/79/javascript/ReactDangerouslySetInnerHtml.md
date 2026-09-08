## Verdict

Confirmed exploitable. Untrusted API response rendered directly into `dangerouslySetInnerHTML` without sanitization.

## Source

API response `ticket.description` originates from `fetch(/api/tickets/{ticketId})` and flows directly to the sink at line 24 without any intermediate validation or encoding.

## Fix

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

    return (
        <article className="ticket-detail">
            <h2>{ticket.subject}</h2>
            <p className="meta">Submitted by {ticket.submitterName}</p>
            <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(ticket.description) }} />
        </article>
    );
}

export default TicketDetail;
```

## Explanation

The vulnerability was caused by passing untrusted API response data directly to `dangerouslySetInnerHTML`, which renders raw HTML without any filtering. An attacker controlling the API response could inject malicious scripts (e.g., `<img onerror="alert('XSS')">` or `<script>` tags) that execute in the victim's browser.

The fix applies `DOMPurify.sanitize()` to the untrusted `ticket.description` before rendering. DOMPurify removes all executable contexts (scripts, event handlers, dangerous attributes) while preserving safe HTML formatting. The sanitized output is safe to pass to `dangerouslySetInnerHTML` because it contains only data, not executable code.

DOMPurify should be at version 3.4.0 or later to avoid CVE-2026-41238 which affected versions 3.0.1 through 3.3.3 under the default `sanitize()` call.

## Behaviour changes

**Input:** API response with potentially malicious HTML markup (e.g., `<script>alert('xss')</script>`, `<img onerror="...">`)

**Before fix:** Malicious markup rendered as-is; scripts and event handlers execute in the browser.

**After fix:** DOMPurify strips dangerous elements and attributes; only safe HTML structures are rendered. Legitimate content containing `<`, `&`, and quotes (when part of safe HTML) still renders correctly. Malicious payloads are neutralized.

**Side effects:** None. The component's visual output for legitimate ticket descriptions is unchanged. Only malicious payloads are prevented from executing.
