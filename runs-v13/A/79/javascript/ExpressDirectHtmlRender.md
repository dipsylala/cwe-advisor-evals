## Verdict
Confirmed XSS vulnerability. User-supplied query parameter `note` is injected directly into HTML without escaping, allowing an attacker to inject arbitrary JavaScript.

## Source
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

The `closingNote` variable receives untrusted input from `req.query.note` and is inserted directly into the HTML string without escaping. When this HTML is sent to the client, the browser parses and executes any JavaScript embedded in the `closingNote` value.

## Fix
Escape HTML special characters in the `closingNote` before inserting it into the HTML template:

```javascript
const escapeHtml = (text) => {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
};

const closingNote = escapeHtml(req.query.note || '');
```

Alternatively, use the `escape-html` package (a standard Express utility):

```javascript
const escapeHtml = require('escape-html');

const closingNote = escapeHtml(req.query.note || '');
```

## Explanation
HTML escaping converts special characters that have meaning in HTML (`<`, `>`, `&`, `"`, `'`) into their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#039;`). This prevents the browser from interpreting user input as HTML or JavaScript markup.

With escaping applied, an attacker's payload like `<img src=x onerror="alert('XSS')">` becomes the literal text string `&lt;img src=x onerror=&quot;alert('XSS')&quot;&gt;`, which displays as text in the page rather than executing code.

The `req.params.id` and `ticket.subject` values are also from untrusted sources (the URL and data store respectively) and should similarly be escaped if they can contain user-controlled content.
