## Verdict

Confirmed. The handler builds an HTML response by directly interpolating request-controlled values into a template literal and sends it with `res.send()`, with no output encoding. This is reflected/DOM-independent (server-rendered) XSS.

## Source

Two request-controlled values reach the sink unescaped:

- `req.query.note` (assigned to `closingNote` on line 17) - fully attacker-controlled via the `note` query string parameter on `GET /tickets/:id/confirmation`.
- `req.params.id` - the `:id` route parameter, attacker-controlled and echoed into the page twice (in the `<h1>` and implicitly via the lookup), even though it also happens to key the `tickets` object.

Both flow, unescaped, into the `page` template literal (lines 19-27) and out through `res.send(page)` (line 30) as `text/html`.

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

## Explanation

The root cause is manual HTML assembly: the handler builds a full page as a plain string and hands it to `res.send()`, which performs no encoding of its own - it only sets `Content-Type` based on what you pass it. Every value dropped into that string becomes literal markup, so any value an attacker controls - here, the `note` query parameter and the `id` route parameter - can close the surrounding tag and inject a `<script>` or event-handler payload that executes in the victim's browser when the confirmation link is shared or clicked.

The fix applies context-appropriate output encoding at the point each value is written into HTML, using the `escape-html` package (the same encoder Express uses internally, and a common, actively maintained dependency) to convert `&`, `<`, `>`, `"`, and `'` into their HTML entity equivalents. This neutralizes the value as markup while preserving it as visible text, so `<script>alert(1)</script>` renders as inert text in the page rather than executing.

`ticket.subject` and `ticket.status` are also escaped even though they currently come from the fixed, hardcoded `tickets` store rather than user input: this is defense-in-depth, since that store's values could later be populated from a database or user-submitted ticket form without anyone revisiting this rendering code, and escaping known-safe text has no functional cost.

A more durable structural fix, if this project grows beyond a couple of ad hoc routes, is to move off manual template-literal HTML assembly entirely and adopt a view engine with autoescaping by default (e.g. Express's built-in support for EJS in escape mode, Pug, or Handlebars), so that omitting an escape call requires an explicit opt-out rather than being the default behavior. For this single route, wrapping each interpolation is sufficient and keeps the change minimal.

To verify the fix, request the route with a payload such as `GET /tickets/T-1001/confirmation?note=<script>alert(1)</script>` and confirm the response body contains the literal text `&lt;script&gt;alert(1)&lt;/script&gt;` rather than an executable `<script>` tag, and that no alert fires when the response is rendered in a browser.
