## Verdict

Exploitable

## Source

The `bioHtml` parameter is untrusted user input that can contain attacker-controlled HTML or text.

## Fix

**Vulnerable code (line 7):**
```javascript
return `<div class="profile-card" title="${safeBio}">${safeBio}</div>`;
```

**Fixed code:**
```javascript
const DOMPurify = require('dompurify');

function renderProfileCard(bioHtml) {
  const safeBio = DOMPurify.sanitize(bioHtml);

  // Extract plain text from sanitized HTML for attribute context.
  // DOMPurify's threat model excludes attributes, so we extract text content instead.
  const tempDiv = document.createElement('div');
  tempDiv.innerHTML = safeBio;
  const plainBioText = tempDiv.textContent;

  // Escape double quotes in the attribute value for safe placement in the title attribute
  const escapedText = plainBioText.replace(/"/g, '&quot;');

  return `<div class="profile-card" title="${escapedText}">${safeBio}</div>`;
}
```

## Explanation

The vulnerability occurs because `safeBio` (output of `DOMPurify.sanitize()`) is used in two different output contexts on line 7: as HTML body content and as an HTML attribute value. DOMPurify's design scope is limited to HTML re-insertion sinks and explicitly excludes attributes—the sanitizer does not account for attribute-specific escaping rules. By placing sanitized HTML markup into an attribute value context, the code violates DOMPurify's threat model, which could expose it to context-specific XSS vectors.

The fix separates the two contexts: the element content continues to use the sanitized HTML (where DOMPurify is appropriate), while the attribute value uses extracted plain text. The plain text is obtained by creating a temporary DOM element, setting its `innerHTML` to the sanitized HTML, and extracting `textContent`. This removes all markup, leaving only text. The resulting text is then escaped for safe placement inside an HTML attribute by replacing double quotes with `&quot;`.

## Behaviour changes

None. The fix preserves the original return type (a string containing HTML markup) and the element structure. The title attribute now displays plain text instead of attempting to render HTML markup inside it—a semantic correction that matches the attribute's intended purpose while maintaining the original contract and functionality.
