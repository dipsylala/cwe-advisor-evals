## Verdict
Confirmed CWE-79. The `closingNote` query parameter is directly interpolated into the HTML response without escaping, allowing an attacker to inject arbitrary JavaScript.

## Source
Line 17: `const closingNote = req.query.note || '';` reads untrusted query parameter input.
Line 24: `<p>Agent note: ${closingNote}</p>` embeds the unescaped input into HTML markup.
Line 30: `res.send(page)` sends the rendered HTML to the client.

An attacker can craft a URL like `/tickets/T-1001/confirmation?note=<script>alert('XSS')</script>` to execute arbitrary JavaScript in the victim's browser.

## Fix
Use the `escape-html` library to escape HTML entities before embedding user input into the HTML response.

Add `const escapeHtml = require('escape-html');` at the top of the file.

Change line 24 from:
```
<p>Agent note: ${closingNote}</p>
```
to:
```
<p>Agent note: ${escapeHtml(closingNote)}</p>
```

Install the dependency with `npm install escape-html`.

## Explanation
User-supplied input from query parameters, form data, path parameters, and headers must be treated as untrusted and escaped according to the context where it is used. In HTML context, characters like `<`, `>`, `"`, `'`, and `&` must be converted to their HTML entity equivalents (`&lt;`, `&gt;`, `&quot;`, `&#39;`, `&amp;` respectively) to prevent injection attacks.

The `escape-html` library automatically performs this context-appropriate escaping. This prevents the injected script tag from being parsed as markup and ensures it renders as plain text to the user.

Alternatively, use a templating engine with auto-escaping enabled (EJS, Handlebars, Pug) to avoid manual escaping on every insertion, which is less error-prone at scale.
