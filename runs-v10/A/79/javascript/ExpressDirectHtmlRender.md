## Verdict

Real vulnerability. The closing note query parameter is directly interpolated into the HTML response without escaping, allowing injection of arbitrary scripts.

## Source

Line 17 receives untrusted input from the query string:
```javascript
const closingNote = req.query.note || '';
```

Line 24 embeds this unsanitized value into the HTML response:
```javascript
<p>Agent note: ${closingNote}</p>
```

An attacker can craft a URL with `?note=<script>alert('xss')</script>` to inject executable code.

## Fix

Install the `escape-html` package and use it to neutralize HTML special characters:

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

The fix escapes all dynamic values before embedding them in HTML. `escape-html` converts special characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`). This prevents the browser from interpreting user input as code. The note is rendered as literal text, not executable script.

Apply this to all values interpolated into HTML responses where the source is user-controlled or database-sourced without prior escaping.
