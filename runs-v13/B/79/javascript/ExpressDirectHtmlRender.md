## Verdict

Real vulnerability. Cross-Site Scripting via unencoded user input in HTML response body.

## Source

User-supplied query parameter `req.query.note` (line 17) flows untrusted into the HTML template string without encoding.

## Fix

Add HTML encoding using the `escape-html` package. At the top of the file add:

```javascript
const escapeHtml = require('escape-html');
```

Replace line 17-24 with:

```javascript
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
```

The change wraps `${closingNote}` with `escapeHtml()` on line 24 to encode HTML special characters.

## Explanation

The vulnerability occurs because `closingNote` is embedded directly into the HTML template without encoding. An attacker can inject payload like `<img src=x onerror="alert('XSS')">` as the `note` query parameter, which executes in the victim's browser when `res.send(page)` renders the response.

The fix applies HTML context-specific encoding via `escape-html`, converting special characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`). This keeps the data as text content, not executable markup. The `escape-html` package is a standard Node.js utility for this purpose and is widely available.

The encoding is applied at the output sink (the template insertion point) rather than on input, following defense-in-depth principle: if this value is rendered in multiple contexts or re-used later, each sink applies appropriate encoding for its context.

## Behaviour changes

None. Legitimate content containing HTML metacharacters (`<`, `>`, `&`, quotes) continues to render correctly as text, now safely encoded. Malicious payloads are neutralized: `<script>alert(1)</script>` appears as literal text instead of executing.
