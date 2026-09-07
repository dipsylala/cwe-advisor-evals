## Verdict

Exploitable. Untrusted user input from `req.query.note` flows directly into the HTML response without encoding, enabling script injection.

## Source

`req.query.note` (query parameter) at line 17, also `req.params.id` and `ticket.subject` flowing through to the HTML output.

## Fix

**Vulnerable code (lines 17-30):**
```javascript
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

res.send(page);
```

**Fixed code:**
```javascript
const escape = require('escape-html');

app.get('/tickets/:id/confirmation', (req, res) => {
    const ticket = tickets[req.params.id];
    if (!ticket) {
        return res.status(404).send('Ticket not found');
    }

    const closingNote = req.query.note || '';

    const page = `
        <html>
            <body>
                <h1>Ticket ${escape(req.params.id)} - ${escape(ticket.subject)}</h1>
                <p>Status: ${escape(ticket.status)}</p>
                <p>Agent note: ${escape(closingNote)}</p>
            </body>
        </html>
    `;

    res.send(page);
});
```

Add to package.json dependencies:
```json
"dependencies": {
  "escape-html": "^1.0.3"
}
```

## Explanation

The original code embeds untrusted query parameters and data store values directly into an HTML string without output encoding. An attacker can inject script tags or event handlers via the `note` parameter (e.g., `?note=<script>alert(1)</script>`), which executes in the victim's browser. The fix wraps all dynamic values with `escape-html`, which converts HTML metacharacters (`<`, `>`, `&`, `"`, `'`) to their entity equivalents, neutralizing script injection while preserving the readability of legitimate content containing these characters. The `escape-html` package is widely used in Node.js/Express applications for this purpose and is maintained as a stable utility.

## Behaviour changes

None. The `escape-html` function only affects the encoding of the output string—no return values, error handling, or response structure change. The Content-Type is still inferred as `text/html`, and `res.send()` continues to send the response and end the connection as before. The original HTML structure and intent remain intact; only the data embedded within it is safely encoded.
