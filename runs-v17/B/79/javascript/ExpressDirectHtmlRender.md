## Verdict

Exploitable. Untrusted user input from `req.query.note` is embedded directly into an HTML template literal without escaping and sent to the client via `res.send()`, allowing injection of arbitrary HTML and JavaScript.

## Source

`req.query.note` (line 17) - user-controlled query parameter passed to the route handler without validation or constraints.

## Fix

### File: ExpressDirectHtmlRender.js

```javascript
const express = require('express');
const app = express();

// Set view engine to EJS
app.set('view engine', 'ejs');
app.set('views', './views');

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

    // Render template with data automatically escaped by EJS
    res.render('ticket-confirmation', {
        ticketId: req.params.id,
        ticket: ticket,
        closingNote: closingNote
    });
});

module.exports = app;
```

### File: views/ticket-confirmation.ejs

```ejs
<html>
    <body>
        <h1>Ticket <%= ticketId %> - <%= ticket.subject %></h1>
        <p>Status: <%= ticket.status %></p>
        <p>Agent note: <%= closingNote %></p>
    </body>
</html>
```

## Explanation

The fix replaces unsafe template-literal HTML construction with EJS, a templating engine that automatically HTML-encodes output by default. The `<%= %>` syntax in EJS escapes HTML entities in the embedded variables (converting `<` to `&lt;`, `&` to `&amp;`, etc.), preventing the injection of executable scripts. The untrusted `closingNote` value is now safely rendered as text content rather than raw HTML, closing the XSS vector while maintaining full functionality for legitimate inputs containing special characters.

## Behaviour changes

- Changed from `res.send(page)` to `res.render('ticket-confirmation', {...})`, which requires EJS template engine to be configured as Express's view engine
- HTML template is now in a separate file (`views/ticket-confirmation.ejs`) instead of built as a string in the route handler
- Data is passed to the template as an object rather than embedded in a template literal
- All template variables are automatically escaped by EJS's `<%= %>` syntax, providing context-aware HTML entity encoding at the output sink
- Requires EJS to be available as a dependency and `views/` directory to exist in the application directory; these are standard patterns in Express applications and introduce no functional or security regressions
