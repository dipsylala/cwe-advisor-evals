## Verdict

Confirmed. `ticket.description` is attacker-controlled free text (a customer-submitted ticket
field, returned unmodified by the API) that reaches `dangerouslySetInnerHTML`, React's raw-HTML
injection sink. Any HTML/JS a customer types into the "Describe your issue" field is parsed and
executed in the browser of whoever views the ticket (support staff), giving stored XSS.

## Source

`ticket.description`, from the `useEffect` fetch of `/api/tickets/${ticketId}` (line 10-12),
assigned into component state via `setTicket(data)` and read back out at line 24. The comment
above the API states this field is "the free-text description the customer typed ... The API
returns that text unmodified" - no server-side sanitization or encoding can be assumed.

## Fix

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
            <p className="description">{ticket.description}</p>
        </article>
    );
}

export default TicketDetail;
```

## Explanation

The description is plain customer-typed text with no legitimate need to render as HTML, so the
correct fix is to remove `dangerouslySetInnerHTML` entirely and render `ticket.description` as a
normal JSX child (`{ticket.description}`). React escapes text interpolated this way by default,
so any markup the customer typed is displayed as literal characters instead of being parsed as
DOM elements or scripts - closing the injection without needing an HTML sanitizer.

If the product genuinely requires the description to support rich formatting (e.g. a markdown or
limited-HTML editor upstream), the alternative is to keep `dangerouslySetInnerHTML` but sanitize
the value immediately before render with a maintained allowlist-based sanitizer such as DOMPurify
(`DOMPurify.sanitize(ticket.description)`), never trusting that the API already sanitized it.
For this case - a plain "describe your issue" text field - switching to plain-text rendering is
simpler, avoids a new dependency, and eliminates the sink entirely rather than mitigating it.
