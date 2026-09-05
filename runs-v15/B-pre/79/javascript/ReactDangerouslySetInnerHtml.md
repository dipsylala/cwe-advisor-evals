## Verdict

Exploitable. The component renders untrusted user input from an API response directly into the page as HTML via `dangerouslySetInnerHTML` without any sanitization or encoding. An attacker can inject arbitrary HTML and JavaScript by including malicious content in the ticket description field.

## Source

`ticket.description`: user-controlled free-text field from an API response at `/api/tickets/${ticketId}` (line 10-12), returned unmodified by the backend and passed to the React component via state.

## Fix

**Vulnerable code:**
```jsx
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
            <div dangerouslySetInnerHTML={{ __html: ticket.description }} />
        </article>
    );
}

export default TicketDetail;
```

**Fixed code:**
```jsx
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

**Package.json dependency:**
Add DOMPurify to the project:
```json
"dependencies": {
  "dompurify": "^3.4.0"
}
```

## Explanation

The fix wraps the untrusted `ticket.description` value with `DOMPurify.sanitize()` before passing it to `dangerouslySetInnerHTML`. DOMPurify is a purpose-built HTML sanitizer that removes executable scripts while preserving safe markup. Version 3.4.0 or later is required to close CVE-2026-41238, which affected versions 3.0.1 through 3.3.3 under the default `sanitize(input)` call used here.

This transforms the data from untrusted to trusted at the point it enters the sink, implementing the context-aware defence-in-depth approach outlined in CWE-79 guidance: output encoding (sanitization) happens at each rendering sink, not once on input. The component can still display rich HTML formatting in customer-provided ticket descriptions while preventing script injection attacks.

## Behaviour changes

None. DOMPurify.sanitize() preserves safe HTML and text formatting while stripping only executable content. The return value is a sanitized string suitable for `dangerouslySetInnerHTML` in place of the original, and the component's visible output for legitimate ticket content remains unchanged.
