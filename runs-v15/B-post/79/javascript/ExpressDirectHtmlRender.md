## Verdict

Exploitable

## Source

Untrusted HTTP query parameter `req.query.note` (line 17)

## Fix

**Vulnerable code:**
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
// HTML escape function to neutralize special characters
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    };
    return text.replace(/[&<>"']/g, char => map[char]);
}

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
```

## Explanation

The closingNote value comes directly from an untrusted HTTP query parameter and is inserted into HTML without escaping. An attacker can inject arbitrary HTML and JavaScript, for example `?note=<img src=x onerror="alert(document.cookie)">`, which executes in the victim's browser. The fix applies context-aware HTML entity encoding to the closingNote before rendering. This converts special characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents, ensuring they are treated as data rather than code. The escapeHtml function is a standard pattern for output encoding at HTML context sinks like res.send().

## Behaviour changes

None. The escapeHtml function preserves the semantic meaning of the content while preventing code injection. Legitimate text containing `<`, `&`, or quotes continues to display correctly (as their entity representations, which browsers render visually as the original characters).
