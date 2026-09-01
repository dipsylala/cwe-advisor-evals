## Verdict

Exploitable. Untrusted user input from `req.query.note` is directly interpolated into an HTML template literal and sent to the client without encoding, allowing arbitrary HTML/JavaScript injection.

## Source

`req.query.note` query parameter (line 17), treated as untrusted external input.

## Fix

**Vulnerable code (line 17-30):**

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
const closingNote = escape(req.query.note || '');

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

## Explanation

The `closingNote` value originates from the untrusted `req.query.note` parameter and is directly embedded in the HTML template literal sent via `res.send()`. Without encoding, an attacker can inject malicious payloads—for example, `?note=<script>alert('XSS')</script>`—which execute in victims' browsers. The fix applies HTML entity encoding using the `escape-html` package at the source before interpolation, converting special characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`). This ensures the value is treated as text content, not executable markup, eliminating the injection vector while preserving display of the closing note's actual text.

## Behaviour changes

None. The fix preserves the original behavior of displaying the agent's closing note as text in the HTML response, with only the encoding transformation applied to make the output safe. The page structure, content, and rendering remain unchanged—special characters in the closing note are still visible but as escaped entities, which browsers render as their intended characters.
