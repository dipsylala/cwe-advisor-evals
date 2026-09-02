## Verdict

Exploitable. Confidence: high.

## Source

`ticket.description`, part of the JSON body returned by `fetch(\`/api/tickets/${ticketId}\`)` (line 10-12) and stored into component state via `setTicket(data)`. Per the file's own header comment, this is "the free-text description the customer typed into the 'Describe your issue' field when they submitted the ticket," and "the API returns that text unmodified" - so the value is attacker-controlled (any support customer can type into that field) and reaches the render path with no encoding or sanitization applied anywhere between the fetch and the render.

## Fix

Vulnerable code (line 24):

```jsx
{/* SAST FINDING: CWE-79 reported here. Sink is the next statement. */}
<div dangerouslySetInnerHTML={{ __html: ticket.description }} />
```

Fixed code:

```jsx
<div>{ticket.description}</div>
```

## Explanation

`dangerouslySetInnerHTML` bypasses React's default output encoding and inserts the given string into the DOM as raw HTML, so a description like `<img src=x onerror=alert(document.cookie)>` executes in every browser that views the ticket. The field is a plain free-text support-ticket description with no stated requirement for rich HTML formatting, so the correct fix is React's primary defence for this CWE: drop `dangerouslySetInnerHTML` and render the value as ordinary JSX child content (`{ticket.description}`), which React auto-escapes (HTML-entity-encodes `<`, `>`, `&`, quotes) before it reaches the DOM. This closes the weakness without adding a dependency, and is preferred over sanitizing with DOMPurify because the source data was never meant to contain markup in the first place - DOMPurify is the right tool only when a field intentionally accepts rich HTML.

## Behaviour changes

- Any literal HTML markup a customer typed into the description (e.g. `<b>` or a stray `<`) is now displayed as visible text instead of being parsed as HTML - this is the security fix itself: the sink previously interpreted the field as HTML, and the field is plain free text, so that interpretation was never correct behaviour.
- The wrapping element changes from `<div dangerouslySetInnerHTML={...} />` (no children, HTML injected as innerHTML) to `<div>{ticket.description}</div>` (text child, React-escaped). No other props or elements changed; the parent `<article className="ticket-detail">` is untouched.
- No library added and no version/dependency change required.
