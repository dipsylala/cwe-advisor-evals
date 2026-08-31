## Verdict

- **CWE ID:** CWE-79 (Improper Neutralization of Input During Web Page Generation - Cross-site Scripting)
- **Location:** `ExpressDirectHtmlRender.js`, line 30 (`res.send(page)`)
- **Verdict:** exploitable
- **Confidence:** high

## Source

Route: `GET /tickets/:id/confirmation`.

Two attacker-controlled values reach the sink without encoding:

- `req.query.note` (aliased to `closingNote`) - an Express query-string parameter, fully attacker-controlled, interpolated at line 24 (`Agent note: ${closingNote}`).
- `req.params.id` - an Express route parameter, also attacker-controlled (a URL path segment is not implicitly safe), interpolated at line 22 (`Ticket ${req.params.id} - ...`).

Both values flow, unmodified, into the `page` template literal (lines 19-27), which is then written verbatim to the response body via `res.send(page)` (line 30) - a sink the JavaScript CWE-79 guidance names explicitly (`res.send()`/`res.write()` built from a template literal). No validation, encoding, or sanitization occurs anywhere between source and sink. `ticket.subject` and `ticket.status` (lines 22-23) come from the server-side `tickets` in-memory store, not from the request, so they are not part of the taint path.

An attacker who gets a victim to open a URL such as `/tickets/T-1001/confirmation?note=<script>...</script>` gets that script reflected and executed in the victim's browser session.

## Fix

No third-party library is required or recommended by the loaded guidance for this case - the code is not using a template engine (EJS/Pug/Handlebars) or DOMPurify-scoped rich HTML, so the fix is a plain context-appropriate HTML encoding of the two untrusted values before they enter the markup.

**Vulnerable code:**

```javascript
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
                <h1>Ticket ${req.params.id} - ${ticket.subject}</h1>
                <p>Status: ${ticket.status}</p>
                <p>Agent note: ${closingNote}</p>
            </body>
        </html>
    `;

    // SAST FINDING: CWE-79 reported here. Sink is the next statement.
    res.send(page);
});
```

**Fixed code:**

```javascript
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
                <h1>Ticket ${escapeHtml(req.params.id)} - ${ticket.subject}</h1>
                <p>Status: ${ticket.status}</p>
                <p>Agent note: ${escapeHtml(closingNote)}</p>
            </body>
        </html>
    `;

    res.send(page);
});
```

## Explanation

`escapeHtml()` HTML-entity-encodes the five characters that let a string escape HTML body context and be reinterpreted as markup (`&`, `<`, `>`, `"`, `'`). It is applied at the point each untrusted value is written into the template literal - `req.params.id` and `closingNote` - which is the sink-adjacent encoding the guidance calls for ("encode at each output sink"), rather than an upstream input filter that a differently-shaped payload could bypass. `ticket.subject` and `ticket.status` are left untouched because they originate from the server-side `tickets` store, not from the request, so they carry no taint and encoding them would be an unjustified change. With both untrusted values encoded, any HTML metacharacters they contain render as literal text instead of being parsed as tags or attributes, closing the reflected-XSS path into `res.send()`.

## Behaviour changes

- A ticket ID or closing note that contains `&`, `<`, `>`, `"`, or `'` now renders as the literal character in the browser (via its HTML entity) instead of being parsed as markup. Visually identical for ordinary text; the underlying HTML source differs, which is the intended fix.
- `tickets[req.params.id]` lookup, the 404 branch, and `ticket.subject`/`ticket.status` rendering are unchanged.
- No change to response status, headers, or `Content-Type` (`res.send()` still receives a string).

**Assumption:** `req.params.id`, in addition to the explicitly-flagged `req.query.note`, was treated as attacker-controlled and in scope for the fix, since Express route parameters are taken from the raw URL path and are not sanitized by the framework before being made available on `req.params`.
