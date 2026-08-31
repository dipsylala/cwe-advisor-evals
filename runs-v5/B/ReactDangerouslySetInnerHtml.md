## Verdict

exploitable (high confidence)

- **cwe_id**: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting'))
- **location**: `ReactDangerouslySetInnerHtml.js`, line 24

## Source

`ticket.description`, one field of the JSON body returned by `fetch(\`/api/tickets/${ticketId}\`)` (line 10-12) and stored into component state via `setTicket(data)`. Per the file's own header comment, this is "the free-text description the customer typed into the 'Describe your issue' field when they submitted the ticket," and "the API returns that text unmodified" - i.e. attacker-controlled input with no server-side encoding or sanitization applied anywhere on the path from submission to this render. No validation, allowlisting, or escaping occurs between the fetch response and the sink.

## Fix

Vulnerable code:

```jsx
    return (
        <article className="ticket-detail">
            <h2>{ticket.subject}</h2>
            <p className="meta">Submitted by {ticket.submitterName}</p>
            {/* SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement. */}
            <div dangerouslySetInnerHTML={{ __html: ticket.description }} />
        </article>
    );
```

Fixed code:

```jsx
    return (
        <article className="ticket-detail">
            <h2>{ticket.subject}</h2>
            <p className="meta">Submitted by {ticket.submitterName}</p>
            <div className="description">{ticket.description}</div>
        </article>
    );
```

## Explanation

`dangerouslySetInnerHTML` bypasses React's default output encoding and inserts the given string into the DOM as raw HTML, so an attacker who controls `ticket.description` (any customer who can submit a support ticket) can embed `<script>`, an `<img onerror=>`, or other markup that executes in the browser of anyone who later views that ticket - stored XSS. The description field is free text, not a field this application intends to contain markup, so the correct fix per the loaded guidance's primary defence is to stop bypassing the framework: render `ticket.description` as a normal JSX expression child (`{ticket.description}`) instead of through `dangerouslySetInnerHTML`. React auto-escapes JSX expression children, converting any HTML-significant characters in the string to their entity equivalents before insertion, so the same value now displays as literal text instead of being parsed and executed. No third-party sanitizer (e.g. DOMPurify) is needed here because the field is not meant to carry HTML at all; DOMPurify would only be the correct tool if the product intentionally supported rich-text ticket descriptions.

## Behaviour changes

- The `dangerouslySetInnerHTML` prop and its wrapping `{{ __html: ... }}` object are removed; the `<div>` now takes `ticket.description` as a plain child instead of a raw-HTML prop. This is the sink change that closes the weakness and is not a side effect.
- Any HTML markup a customer previously typed into the description (intentionally or maliciously) was rendered as live markup; after the fix it renders as visible literal text (e.g. a literal `<b>` string instead of bold text). This is the intended effect of the fix, not a regression, since the field is untrusted free text.
- Added `className="description"` to the `div`. This is a cosmetic addition with no security purpose, included only so the previously bare `<div>` retains a stable hook for styling once it holds a text node instead of injected markup; it can be dropped to keep the diff strictly minimal if styling is not desired.
- Not applied, flagged for awareness: plain-text JSX rendering does not preserve newlines the customer typed (HTML collapses whitespace by default), whereas the raw-HTML version happened to render literal `<br>` tags or newlines-as-HTML if the customer had entered any. If preserving visual line breaks in free text is a product requirement, add `style={{ whiteSpace: 'pre-wrap' }}` to the `div` rather than reintroducing HTML rendering of user content.
