## Verdict

Confirmed. `ticket.description` is customer-submitted free text returned unmodified by the API, and it is rendered via `dangerouslySetInnerHTML`, which bypasses React's default output encoding. A customer who includes an `<img onerror=...>`, `<script>`-equivalent markup, or an inline event handler in the ticket description gets it parsed and executed as HTML/JS in the browser of anyone who later views that ticket (support agents, other staff) - stored XSS.

## Source

`ticket.description`, obtained from `fetch(`/api/tickets/${ticketId}`)` at line 10-12 and stored in component state via `setTicket(data)`. The comment above the component states the API returns the customer's "Describe your issue" free-text field unmodified, so this value is attacker-controlled and untrusted.

## Fix

```jsx
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
            <p className="description">{ticket.description}</p>
        </article>
    );
}

export default TicketDetail;
```

If the description needs to preserve the customer's line breaks, add `white-space: pre-wrap` to the `.description` class in CSS rather than reintroducing HTML rendering - this keeps the value passing through JSX's default text interpolation, which HTML-encodes it automatically.

## Explanation

`dangerouslySetInnerHTML` tells React to skip its normal escaping and inject the given string as raw HTML into the DOM. It is meant for content the application already trusts (e.g., HTML generated server-side from a controlled markdown pipeline, or output already passed through a sanitizer) - not for verbatim user input. Here `ticket.description` is exactly the kind of value it should never receive: unmodified customer-typed text.

The fix replaces `<div dangerouslySetInnerHTML={{ __html: ticket.description }} />` with ordinary JSX interpolation, `{ticket.description}`. React treats interpolated expressions as text content, not markup, so any `<`, `>`, `&`, or quote characters are rendered literally and cannot break out into an element or attribute - no library or manual escaping is needed for this case, since JSX's built-in encoding already does the job.

Removing `dangerouslySetInnerHTML` entirely is preferable to sanitizing and keeping it, because the ticket description has no legitimate need to contain HTML markup - it is a plain-text issue description. If a future requirement genuinely needs to render limited rich text (e.g., a WYSIWYG editor's output), that content should be run through a maintained HTML sanitizer (such as DOMPurify) immediately before assignment to `__html`, with an explicit allowlist of tags/attributes, rather than trusting the source. For this ticket-description field, plain-text rendering is the correct and sufficient fix.
