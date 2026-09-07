## Verdict
CONFIRMED - CWE-79 Cross-site Scripting vulnerability in attribute context.

## Source
Line 7 of profileCard.js: `title="${safeBio}"` receives HTML-sanitized content intended for body insertion, not attribute insertion.

## Fix

### File: profileCard.js
```javascript
const DOMPurify = require('dompurify');

function renderProfileCard(bioHtml) {
  const safeBio = DOMPurify.sanitize(bioHtml);
  const safeTitle = DOMPurify.sanitize(bioHtml, { ALLOWED_TAGS: [] });

  return `<div class="profile-card" title="${safeTitle}">${safeBio}</div>`;
}

module.exports = { renderProfileCard };
```

## Explanation
DOMPurify's default sanitization (`ALLOWED_TAGS` includes safe HTML tags) produces output suitable for HTML body content, where tags like `<b>` and `<i>` are valid. However, when this output is inserted into an HTML attribute value, those tags become invalid and can break the attribute context.

The fix creates a separate sanitization pass with `ALLOWED_TAGS: []`, which removes all HTML markup and produces text-only content safe for attribute insertion. The body content retains the original formatted sanitization, while the title attribute uses the text-only version, eliminating the attribute-context XSS vector.
