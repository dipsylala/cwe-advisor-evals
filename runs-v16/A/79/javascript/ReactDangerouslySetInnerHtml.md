## Verdict
CWE-79 confirmed. The `ticket.description` field comes from an untrusted API response and is rendered directly into the DOM via `dangerouslySetInnerHTML` without sanitization, allowing arbitrary script injection.

## Source
Line 24 uses `dangerouslySetInnerHTML` with unsanitized user input:
```javascript
<div dangerouslySetInnerHTML={{ __html: ticket.description }} />
```

The `ticket.description` is fetched from `/api/tickets/{ticketId}` and contains free-text user input that has not been validated or sanitized.

## Fix
Sanitize the HTML using DOMPurify before rendering:

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

Install DOMPurify: `npm install dompurify`

## Explanation
`dangerouslySetInnerHTML` bypasses React's HTML escaping and directly inserts raw HTML into the DOM. When combined with untrusted user input, this allows attackers to inject malicious scripts or event handlers (e.g., `<img src=x onerror="alert('XSS')">`).

DOMPurify removes dangerous elements and attributes while preserving safe HTML markup. Applying `DOMPurify.sanitize()` to `ticket.description` before passing it to `dangerouslySetInnerHTML` prevents the injection while allowing legitimate HTML formatting in ticket descriptions.

If HTML formatting is not required, the safer alternative is to render the description as plain text: `<p>{ticket.description}</p>`, which automatically escapes all special characters.
