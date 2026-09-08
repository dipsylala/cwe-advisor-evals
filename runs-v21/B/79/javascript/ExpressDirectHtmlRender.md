## Verdict

Exploitable

## Source

`req.query.note` - attacker-controlled query parameter at line 17

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
                <h1>Ticket ${req.params.id} - ${escapeHtml(ticket.subject)}</h1>
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

The vulnerability occurs because the untrusted `closingNote` value from `req.query.note` is directly interpolated into the HTML template literal without encoding, allowing an attacker to inject arbitrary HTML and JavaScript. The fix applies context-aware HTML entity encoding using the `escape-html` package at the output sink. The `escapeHtml()` function converts special characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents, ensuring the data remains data rather than executable code when rendered in the HTML body context. This is applied to `closingNote` and the other values inserted into the HTML to provide defence-in-depth, since `ticket.subject` and `ticket.status` could potentially become untrusted in a broader application context.

## Behaviour changes

None. The `escape-html` function operates as a pure transformation on its input string and returns the escaped result without modifying any other behaviour. The `res.send()` call receives the same HTML structure with identical rendering semantics for legitimate content, and the return value and exception handling remain unchanged.

**Assumptions:** The `escape-html` package is available from npm (standard dependency in the Node.js ecosystem, widely used with Express). No version floor is specified in the CWE guidance, so the minimum required version should be verified against current security advisories before deployment.

**Verification:** Syntax check passed with `node --check` on the fixed code.
