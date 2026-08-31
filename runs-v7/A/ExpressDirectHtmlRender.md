## Verdict
**Confirmed CWE-79 (Cross-site Scripting)**

The `closingNote` parameter from `req.query.note` is directly embedded in HTML output without escaping, allowing an attacker to inject arbitrary HTML and JavaScript via the query string.

## Source
Line 24: `<p>Agent note: ${closingNote}</p>`

The `closingNote` variable is assigned from `req.query.note` (line 17) and inserted directly into the template string without any HTML entity encoding.

## Fix
Import and use the `escape-html` package to sanitize user input before embedding it in HTML:

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
                <h1>Ticket ${req.params.id} - ${ticket.subject}</h1>
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
The vulnerability occurs because user-supplied input from `req.query.note` is directly interpolated into an HTML response. An attacker can inject scripts, such as `?note=<script>alert('XSS')</script>`, which execute in the victim's browser.

The fix wraps the untrusted input with `escapeHtml()`, which converts characters like `<`, `>`, `&`, `"`, and `'` into their corresponding HTML entities (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`). This ensures that user input is treated as text content rather than markup, preventing the browser from interpreting injected scripts.

The `escape-html` package is a standard Node.js module for this purpose and is production-ready with no additional dependencies.
