## Verdict

The code passes unsanitized user input directly into the DOM via `dangerouslySetInnerHTML`, creating a Cross-Site Scripting vulnerability. An attacker can craft a malicious ticket description containing script tags or event handlers that execute in the browser.

## Source

The vulnerability originates at line 10-12 where `ticket.description` is fetched from an untrusted API endpoint:

```
fetch(`/api/tickets/${ticketId}`)
    .then((res) => res.json())
    .then((data) => setTicket(data));
```

The `ticket.description` field is user-controlled input (the customer's free-text description from the "Describe your issue" field), returned unmodified by the API.

## Fix

### File: ReactDangerouslySetInnerHtml.js

```javascript
import React, { useEffect, useState } from 'react';

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
            <div>{ticket.description}</div>
        </article>
    );
}

export default TicketDetail;
```

## Explanation

The fix replaces `dangerouslySetInnerHTML={{ __html: ticket.description }}` with direct JSX text rendering `{ticket.description}`. 

React's JSX syntax automatically escapes text content inserted via curly braces, converting dangerous characters like `<`, `>`, and `&` into their HTML entity equivalents. This prevents the browser from interpreting user input as markup or executable code.

Since the ticket description is free-text content from a customer (not rich HTML that needs to be preserved), plain text rendering is the appropriate defence. This leverages React's built-in auto-escaping mechanism rather than attempting to sanitize HTML, which is simpler and less error-prone for text-only content.

