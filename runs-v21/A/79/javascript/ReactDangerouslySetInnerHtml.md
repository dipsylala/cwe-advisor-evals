## Verdict
CWE-79 confirmed. The code renders untrusted user input (ticket.description from the API) as raw HTML using dangerouslySetInnerHTML, allowing an attacker to inject malicious scripts through the ticket description field.

## Source
Line 24 in ReactDangerouslySetInnerHtml.js:
```javascript
<div dangerouslySetInnerHTML={{ __html: ticket.description }} />
```

The ticket.description comes from an API response and is used directly without sanitization or encoding. Since the field is free-text input from users, an attacker can submit a description containing script tags or event handlers that will execute in the browser.

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
React's JSX automatically escapes string content when rendering it as text. By removing `dangerouslySetInnerHTML` and rendering ticket.description as a text node inside the div, any HTML or script tags in the user's input are treated as literal text and displayed safely to the user without executing. This is the correct treatment for customer-submitted free-text fields that should not contain formatted HTML.
