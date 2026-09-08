## Verdict

Valid. The code sanitizes untrusted input with DOMPurify for HTML body context but then uses the result in an HTML attribute without attribute-specific encoding, which violates DOMPurify's stated scope and leaves the attribute value vulnerable to breakout.

## Source

Line 7 in `profileCard.js`: The template literal places `safeBio` in the `title` attribute (`title="${safeBio}"`) after sanitizing it with `DOMPurify.sanitize()`. DOMPurify's threat model explicitly excludes attributes - the result is safe for HTML body content but not for attribute context, where different escaping rules apply and quote-breaking payloads can escape the attribute boundary to inject event handlers.

## Fix

### File: profileCard.js

```javascript
const DOMPurify = require('dompurify');

function renderProfileCard(bioHtml) {
  const safeBio = DOMPurify.sanitize(bioHtml);
  
  // HTML attribute encoding for attribute context
  const attributeEncoded = safeBio
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  return `<div class="profile-card" title="${attributeEncoded}">${safeBio}</div>`;
}
```

## Explanation

DOMPurify.sanitize() safely neutralizes XSS in HTML body content by stripping dangerous tags and attributes. However, its protection is specific to that context. When placing its output into an HTML attribute like `title`, the encoding boundary changes: a payload that DOMPurify leaves intact for body content (because it is not a complete tag) can break out of the attribute boundary in quote-delimited context and inject attributes or event handlers. For example, `" onerror="` would remain in the body-sanitized output but would escape the `title` attribute and become a live event handler.

The fix applies standard HTML attribute entity encoding (`&`, `"`, `<`, `>`) to the value used in the attribute while retaining DOMPurify's sanitization for the body content. This follows the guidance principle: "Apply context-aware output encoding specific to where data appears" and "Encode at each output sink" - DOMPurify for body, attribute encoding for attributes.

## Behaviour changes

Legitimate content containing HTML special characters now has those characters entity-encoded when they appear in the `title` attribute (e.g., `&` becomes `&amp;`, `"` becomes `&quot;`). This is the correct and expected rendering for attribute context - browsers decode entities when displaying title text. The HTML body content retains DOMPurify's existing sanitization. The function's return type and structure are unchanged.
