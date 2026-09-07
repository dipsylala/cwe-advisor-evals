## Verdict

CONFIRMED. The code places DOMPurify-sanitized output into an HTML attribute context (`title="${safeBio}"`), which is outside DOMPurify's documented threat model and requires context-specific encoding.

## Source

`bioHtml` parameter (untrusted input from caller) → `DOMPurify.sanitize(bioHtml)` produces `safeBio` → placed into two sinks:
1. `title="${safeBio}"` (attribute context, line 7)
2. `${safeBio}` (HTML body context, line 7)

## Fix

### File: profileCard.js

```javascript
const DOMPurify = require('dompurify');

function escapeHtmlAttribute(text) {
  if (!text) return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function renderProfileCard(bioHtml) {
  const safeBio = DOMPurify.sanitize(bioHtml);
  const safeBioAttribute = escapeHtmlAttribute(safeBio);

  return `<div class="profile-card" title="${safeBioAttribute}">${safeBio}</div>`;
}
```

## Explanation

The vulnerability occurs because DOMPurify's threat model explicitly excludes attribute contexts. While DOMPurify effectively removes script tags and event handlers for HTML body insertion, its output is not guaranteed safe when placed in HTML attributes. The fix applies context-specific encoding: DOMPurify sanitization for the HTML body content (where it is designed to work), and proper HTML attribute escaping for the `title` attribute value. The `escapeHtmlAttribute` function encodes the special characters that could break out of the quoted attribute (`&`, `"`, `<`, `>`). This separates the defense mechanisms by context and aligns with the CWE-79 guidance principle: "Encode at each output sink, not once on input: a value encoded for HTML body text is still unsafe inside... an event-handler attribute."

## Behaviour changes

The `title` attribute value is now HTML-entity-encoded. This ensures that characters like double quotes and ampersands in the bio text are represented as HTML entities rather than raw characters. The visual behaviour remains unchanged: the browser decodes the entities when displaying the tooltip. The HTML body content continues to display sanitized HTML as before (malicious markup removed, safe formatting preserved).
