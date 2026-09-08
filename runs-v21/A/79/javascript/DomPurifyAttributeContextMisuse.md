## Verdict

Real CWE-79 vulnerability. DOMPurify.sanitize() sanitizes for HTML content context, not for attribute context. The same sanitized value used in both `${safeBio}` (HTML body) and `title="${safeBio}"` (attribute) is incorrect because attributes require different handling.

## Source

Line 7 of profileCard.js inserts a value into an HTML attribute after sanitizing it for HTML content:

```
return `<div class="profile-card" title="${safeBio}">${safeBio}</div>`;
```

The `title` attribute receives a value that was sanitized for HTML content, not for attribute context.

## Fix

### File: profileCard.js

```javascript
const DOMPurify = require('dompurify');

function renderProfileCard(bioHtml) {
  const safeBio = DOMPurify.sanitize(bioHtml);
  const safeBioPlainText = DOMPurify.sanitize(bioHtml, { ALLOWED_TAGS: [] });

  return `<div class="profile-card" title="${safeBioPlainText}">${safeBio}</div>`;
}
```

## Explanation

The fix creates two sanitized versions:

1. `safeBio`: Sanitized for HTML content context (with tags allowed). Used in the div body where HTML formatting is desired.
2. `safeBioPlainText`: Sanitized with `ALLOWED_TAGS: []` to extract plain text only. Used in the attribute context where HTML tags are not needed.

Attribute contexts do not require or benefit from HTML; they need plain text to avoid attribute-parsing exploits. By sanitizing once for each context appropriately, both the HTML content and the attribute value are protected against CWE-79.
