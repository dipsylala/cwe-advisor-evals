## Verdict

Confirmed. The code constructs an HTML response using unsanitized user input from the query parameter `req.query.note`, which is directly interpolated into the HTML string without any escaping. This allows an attacker to inject arbitrary HTML and JavaScript.

## Source

Line 17 reads the `closingNote` parameter from `req.query.note` without validation. Line 24 inserts this value directly into an HTML template literal: `<p>Agent note: ${closingNote}</p>`. Line 30 sends the resulting HTML to the client, acting as the taint sink.

An attacker can pass `?note=<script>alert('XSS')</script>` to execute arbitrary JavaScript in the browser of any user viewing the confirmation page.

## Fix

Escape HTML special characters in the user-supplied input before inserting it into the HTML response. Using the `escape-html` package (a standard Node.js library):

```javascript
const escape = require('escape-html');

app.get('/tickets/:id/confirmation', (req, res) => {
    const ticket = tickets[req.params.id];
    if (!ticket) {
        return res.status(404).send('Ticket not found');
    }

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
});
```

Alternatively, use a templating engine with HTML auto-escaping enabled by default (EJS, Handlebars, or Nunjucks), which is the more robust long-term solution for applications with multiple templates.

## Explanation

HTML metacharacters (`<`, `>`, `&`, `"`, `'`) have special meaning in HTML markup. When user input is inserted directly into HTML without escaping, an attacker can break out of the intended context and inject arbitrary tags or scripts. The `escape-html` function converts these characters to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), ensuring they are treated as literal text rather than markup syntax. This prevents script injection while preserving the intended content.
