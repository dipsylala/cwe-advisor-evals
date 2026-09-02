## Verdict

Real vulnerability. Cross-site scripting (XSS) via unescaped query parameter.

## Source

`req.query.note` (line 17) receives untrusted input from the query string. The value is assigned to `closingNote` without validation or sanitization, then embedded directly into an HTML template literal on line 24, and finally sent to the browser via `res.send(page)` on line 30.

Attack vector: `GET /tickets/T-1001/confirmation?note=<img src=x onerror="alert('XSS')">` will execute the injected script in the victim's browser.

## Fix

Apply HTML escaping to the `closingNote` variable before interpolating it into the HTML template:

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

**Dependency:** Add `escape-html` to package.json. This is a standard, widely-maintained npm package for HTML entity encoding.

## Explanation

The fix adds the `escape-html` library import and wraps the untrusted `closingNote` variable with `escapeHtml()` on line 24. This function converts HTML metacharacters (`<`, `>`, `&`, `"`, `'`) into their corresponding HTML entities (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), preventing the injected markup from being parsed as HTML while preserving the intended text display.

The escaping occurs at the output sink (where the data enters the HTML response), applying context-specific encoding for HTML body text as required by the guidance. This ensures that attacker-controlled input remains data rather than executable code.

## Behaviour changes

- Added dependency: `escape-html` npm package (no version changes to application logic)
- Query parameter `note` values containing HTML metacharacters are now rendered as text instead of markup
- Legitimate content such as `"Quote: <50% off>"` will display correctly as literal text
- No changes to application logic, routing, or response structure
