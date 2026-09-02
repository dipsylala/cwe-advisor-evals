## Verdict

CWE-79 (Cross-Site Scripting) confirmed. Untrusted user input from an external API is rendered directly into the DOM via `dangerouslySetInnerHTML` without sanitization, allowing arbitrary script execution in the browser.

## Source

Lines 10–12: `fetch('/api/tickets/${ticketId}')` retrieves ticket data from an external API. The `ticket.description` field is user-controlled (customer-submitted free-text) and returned by the API unmodified.

Line 24: `ticket.description` is rendered into the DOM via `dangerouslySetInnerHTML={{ __html: ticket.description }}`, allowing embedded HTML and scripts to execute.

## Fix

Add DOMPurify as a dependency (version 3.4.0 or later) and sanitize the description before rendering:

```jsx
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

The fix wraps `ticket.description` with `DOMPurify.sanitize()` before passing it to `dangerouslySetInnerHTML`. DOMPurify removes all potentially dangerous HTML and JavaScript, permitting only safe HTML tags and attributes. This prevents XSS attacks while preserving legitimate formatting in customer-submitted descriptions.

The import adds a runtime dependency on DOMPurify (3.4.0+). The version floor of 3.4.0 addresses CVE-2026-41238, which affects earlier versions when using the plain `DOMPurify.sanitize(input)` call. Confirm this dependency is resolved in your package.json and SCA tooling.

## Behaviour changes

**No observable user-facing change for legitimate content.** Malicious scripts, event handlers, and unsafe tags are stripped before rendering:

- Input: `<p>Issue description</p><script>alert('xss')</script>`
  - Before fix: Script executes in the browser (XSS attack succeeds)
  - After fix: Script tag is removed; only `<p>Issue description</p>` renders (attack prevented)

- Input: `<p onclick="alert('xss')">Click me</p>`
  - Before fix: onclick handler executes on click (XSS attack succeeds)
  - After fix: onclick attribute is removed; `<p>Click me</p>` renders safely (attack prevented)

- Input: `<p>Normal formatting with <em>emphasis</em></p>`
  - Before fix: Renders as-is
  - After fix: Renders identically (legitimate HTML preserved)
