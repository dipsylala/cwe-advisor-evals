## Verdict

exploitable

- cwe_id: CWE-79
- location: ReactDangerouslySetInnerHtml.js, line 24
- confidence: high

## Source

`ticket.description`, taken unmodified from the JSON response of `fetch(\`/api/tickets/${ticketId}\`)` (line 10-12) and stored into component state via `setTicket(data)`. Per the file's own comment, this value is the free-text content a customer typed into the "Describe your issue" field when submitting the ticket, and the API returns it unmodified - it is attacker-controlled and carries no server-side encoding or sanitization before reaching the component.

## Fix

### File: ReactDangerouslySetInnerHtml.js

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

## Explanation

The sink was `dangerouslySetInnerHTML={{ __html: ticket.description }}`, which tells React to assign the string directly to the DOM node's `innerHTML`, bypassing React's default text escaping entirely - any HTML or `<script>`/event-handler markup a customer typed into the ticket description executes for whoever views the ticket. The description field is plain, unmodified free text with no legitimate need for HTML rendering (the same comment block that describes the field says the API returns it "unmodified"), so there is no rich-HTML use case that would call for a sanitizer such as DOMPurify. The fix removes `dangerouslySetInnerHTML` and its `__html` object entirely and renders `ticket.description` as an ordinary JSX child expression inside a `<p>`, the same pattern already used two lines above for `ticket.subject` and `ticket.submitterName`. React auto-escapes JSX text children by default, so any HTML-looking characters in the description are rendered as literal, inert text instead of being parsed as markup - this is the primary defence named for React in the knowledge base (`cwe/79/javascript/INDEX.md`: "Use framework built-in escaping mechanisms (React JSX...)"; "Never use `innerHTML`, `dangerouslySetInnerHTML`... with untrusted data").

## Behaviour changes

- The `<div>` sink is now a `<p>` carrying the same `description` styling hook (className changed from none to `"description"` only in the sense that the original `<div>` had no className at all - to keep the element identifiable for existing CSS, `className="description"` was added; if a stylesheet targets `.ticket-detail div` rather than an element type, this selector would need updating). This is the only structural change beyond the sink swap itself, and it exists to keep the element addressable, not to alter security behaviour.
- If the ticket description ever legitimately contained HTML markup, that markup would previously have been rendered as live HTML and now renders as literal visible text (e.g. `<b>` displays as the characters `<b>` rather than bold text). Per the field's own description (customer free text, returned unmodified), this is the correct behaviour for a plain-text field and is not expected to occur in normal use; it is called out here because it is the one user-visible difference the fix produces.
- No new imports, dependencies, or props were introduced. `React`, `useEffect`, and `useState` usage is unchanged.

## Verification

`node --check` cannot be used as-is: Node's parser does not understand JSX syntax regardless of file extension, and it fails identically on the original, unmodified file's `<p>Loading ticket...</p>` JSX (confirmed by running `node --check` against a copy of the file - Node reports `SyntaxError: Unexpected token '<'` at the pre-existing JSX, not at anything the fix touched). The repository has no `package.json`, bundler, or Babel toolchain to transpile and run a real syntax check against. In place of a compiler, a manual review was performed: the fix removes the `dangerouslySetInnerHTML={{ __html: ticket.description }}` prop and its object literal and substitutes a bare JSX expression `{ticket.description}`, an identical construct in form to the pre-existing `{ticket.subject}` (line 21) and `{ticket.submitterName}` (line 22) expressions in the same file, so its validity is established by those working examples. No new symbol, import, package, or API is introduced. JSX tags remain balanced and the element keeps its original position as the third child of the same `<article>` parent.
