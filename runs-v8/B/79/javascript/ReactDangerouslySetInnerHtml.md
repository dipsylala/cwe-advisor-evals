## Verdict

Exploitable. The `ticket.description` field originates from user input (free-text customer ticket description), flows through an API response without sanitization, and is rendered directly into the DOM via `dangerouslySetInnerHTML` on line 24, allowing arbitrary script injection.

## Source

`ticket.description` — untrusted data fetched from `/api/tickets/{ticketId}` API endpoint. The API returns the customer's unmodified free-text input from the "Describe your issue" field at ticket submission. Attackers can inject XSS payloads (e.g., `<img src=x onerror="...">`, `<svg onload="...">`) that execute in the context of any user viewing the ticket.

## Fix

**Vulnerable code (line 24):**
```javascript
<div dangerouslySetInnerHTML={{ __html: ticket.description }} />
```

**Fixed code:**
```javascript
import React, { useEffect, useState } from 'react';
import DOMPurify from 'dompurify';

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

Add DOMPurify as a dependency (minimum version 3.4.0, which fixes CVE-2026-41238 affecting earlier versions under plain `DOMPurify.sanitize(input)` calls).

## Explanation

The fix sanitizes the user-supplied HTML with `DOMPurify.sanitize()` before rendering it. DOMPurify is a purpose-built HTML sanitizer that strips dangerous elements and event handlers (`<script>`, `onerror`, `onload`, etc.) while preserving safe markup structure. By passing only the sanitized result to `dangerouslySetInnerHTML`, the sink still receives a string but one with all XSS payloads removed. This eliminates the injection vector while preserving the ability to render customer-authored rich text (bold, links, lists, etc.) that simple text rendering would lose. The framework guidance identifies DOMPurify as the standard safe pattern for rich HTML in React; `dangerouslySetInnerHTML` is retained because the intention is to preserve HTML formatting rather than strip it entirely.

## Behaviour changes

None. DOMPurify preserves legitimate HTML content (paragraphs, lists, links, emphasis) and removes only the dangerous payloads. The visual output will be identical for benign input and will prevent XSS execution for malicious input. The fix does not alter the return value of `dangerouslySetInnerHTML` (it still returns a React element consumed in JSX), does not introduce new failures or side effects, and does not change the component's interface or contract with its caller.
