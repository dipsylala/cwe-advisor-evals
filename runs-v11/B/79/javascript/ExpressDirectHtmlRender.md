## Verdict

Exploitable. Untrusted user input from `req.query.note` is inserted directly into the HTML response without encoding, allowing arbitrary script injection.

## Source

`req.query.note` (line 17) — untrusted data from HTTP query parameter passed to the application without validation.

## Fix

Add the `escape-html` package dependency and apply HTML entity encoding to user-controlled data before rendering it into the HTML page.

**Vulnerable code (lines 17–30):**

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

// SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
res.send(page);
```

**Fixed code:**

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

The vulnerability occurs because the template literal builds HTML content by directly interpolating the `closingNote` variable, which originates from untrusted user input (`req.query.note`). An attacker can craft a malicious query parameter such as `?note=<script>alert('xss')</script>` which will be rendered as executable JavaScript in the victim's browser.

The fix applies context-specific HTML entity encoding using the `escape-html` package at every point where untrusted or potentially untrusted data is rendered into HTML body context. This transforms special characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), preventing the browser from interpreting user input as code. The escaping is applied at the sink (the template literal) where data enters the HTML output context, following the CWE-79 guidance principle of "encode at each output sink."

Additionally, `ticket.subject` is also escaped for defense-in-depth, even though it is server-controlled, to maintain consistent escaping of all dynamically inserted content.

## Behaviour changes

- **Dependency added**: Requires `escape-html` package to be installed via npm (no version lock specified in the guidance, so version should be confirmed against dependency-check tooling).
- **Import added**: `const escapeHtml = require('escape-html');` at module level.
- **Output change**: User-supplied query parameters and all HTML-special characters in dynamically inserted content are now HTML-encoded in the response, converting `<`, `>`, `&`, and quotes to entity references. This is the intended security fix and does not alter the visual rendering for legitimate input (text containing `<`, `&`, etc. displays correctly as escaped entities).
- **Response content**: No change to HTTP headers or response structure; only the HTML body content is escaped. The `res.send()` call signature and behaviour remain identical.

