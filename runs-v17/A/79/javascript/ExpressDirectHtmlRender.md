## Verdict

Real vulnerability. User-supplied inputs (`req.query.note` and `req.params.id`) are directly interpolated into HTML without escaping, enabling script injection.

## Source

Line 17: `const closingNote = req.query.note || '';`  
Line 22: `<h1>Ticket ${req.params.id} - ${ticket.subject}</h1>`  
Line 24: `<p>Agent note: ${closingNote}</p>`  
Line 30: `res.send(page);`

The `closingNote` and `req.params.id` reach the response HTML without HTML entity encoding.

## Fix

### File: ExpressDirectHtmlRender.js

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

    // SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
    res.send(page);
});

module.exports = app;
```

## Explanation

All user-supplied values and untrusted data are wrapped with `escapeHtml()` before insertion into the response HTML. The `escape-html` package converts characters like `<`, `>`, `"`, `'`, and `&` to their corresponding HTML entities (`&lt;`, `&gt;`, etc.), preventing the browser from interpreting them as markup or script delimiters.

This ensures that input like `<img src=x onerror=alert('XSS')>` renders as visible text rather than executable code. The fix is applied to:
- `req.params.id` (URL parameter)
- `ticket.subject` (internal data that may need sanitization for defense-in-depth)
- `ticket.status` (internal data)
- `closingNote` (query parameter, the primary attack vector)

`escape-html` is a stable, widely-used npm package with no dependencies, making it a safe drop-in for this scenario.
