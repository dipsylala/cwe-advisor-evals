## Verdict

Real vulnerability. DOMPurify's sanitization scope is HTML body context only. Its threat model explicitly excludes attributes. Placing `safeBio` in the `title` attribute misuses DOMPurify and creates an XSS sink.

## Source

`bioHtml` parameter (untrusted input).

## Fix

```javascript
const DOMPurify = require('dompurify');

function renderProfileCard(bioHtml) {
  const safeBio = DOMPurify.sanitize(bioHtml);

  // For the title attribute, extract plain text from the sanitized HTML.
  // DOMPurify is designed for HTML body context only, not attributes.
  const bioText = safeBio.replace(/<[^>]*>/g, '')     // strip HTML tags
                         .replace(/"/g, '&quot;');    // escape quotes for attribute

  return `<div class="profile-card" title="${bioText}">${safeBio}</div>`;
}
```

## Explanation

DOMPurify sanitizes for HTML body re-insertion (the `innerHTML` sink). The guidance explicitly states its threat model excludes attributes: "DOMPurify's stated scope is HTML re-insertion sinks. Its own threat model excludes moving the result into SVG, MathML, XML, an attribute or a rawtext element."

The `title` attribute is an attribute context. Placing `safeBio` directly there creates two issues:

1. **Markup escaping**: The sanitized output may contain HTML tags like `<b>` or `<i>`, which cannot appear as literal markup in an attribute value. In attribute context, these must be text only.

2. **Quote breakout**: If the sanitized content contains unescaped quotes (e.g., from user text containing `"`), the attribute syntax breaks: `title="user's text"onclick="..."` becomes a second attribute handler.

The fix extracts plain text from the sanitized HTML by stripping all tags, then escapes quotes for safe attribute inclusion. The HTML-rich content remains in the body where DOMPurify is designed to protect it; the plain text goes in the attribute.

## Behaviour changes

- The `title` attribute now shows plain text extracted from the bio, with HTML tags removed.
- Rich formatting (bold, italics, links) from `safeBio` appear in the content area, not the title.
- Quotes and angle brackets in the bio text are properly escaped for attribute context, preventing syntax breakout and XSS.
