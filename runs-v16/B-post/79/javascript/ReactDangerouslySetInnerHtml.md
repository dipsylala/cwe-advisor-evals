## Verdict

exploitable

## Source

`ticket.description` - untrusted data from API response (line 12: `res.json()`)

## Fix

**Vulnerable code:**
```javascript
import React, { useEffect, useState } from 'react';

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
            {/* SAST FINDING: CWE-79 - Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') */}
            <div dangerouslySetInnerHTML={{ __html: ticket.description }} />
        </article>
    );
}

export default TicketDetail;
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

## Explanation

The vulnerability exists because `ticket.description` flows from an untrusted API source directly to `dangerouslySetInnerHTML` without sanitization. An attacker controlling the API response can inject arbitrary HTML and JavaScript, which executes in the victim's browser. The fix sanitizes the HTML using DOMPurify version 3.4.0 or later before rendering. DOMPurify removes malicious script tags and event handlers while preserving safe HTML formatting, closing the XSS vector. The library is specified at minimum version 3.4.0 to exclude CVE-2026-41238 which affects earlier versions.

## Behaviour changes

- **Import added:** `DOMPurify` module imported at the top level. Source: the codebase must add `dompurify` to its dependencies (npm package); this is a real dependency that must be present.
- **HTML sanitization applied:** The `ticket.description` value is now passed through `DOMPurify.sanitize()` before rendering. This filters the HTML to remove script tags, event handlers (`onclick`, `onload`, etc.), and other dangerous markup while preserving safe formatting elements. This is a security-relevant change that alters what HTML is ultimately rendered—malicious payloads are rejected, but benign user-supplied HTML with links and formatting is preserved.
- **No other changes:** The function's input/output behavior, error handling, and loading state remain unchanged. The component still receives the ticket data from the API and renders it in the same DOM structure.
