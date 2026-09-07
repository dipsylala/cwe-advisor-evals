## Verdict
Confirmed. CWE-79 Cross-site Scripting vulnerability exists due to context mismatch in sanitization.

## Source
`bioHtml` parameter enters at line 3, passed to `DOMPurify.sanitize()`.

## Fix
```javascript
const DOMPurify = require('dompurify');

function renderProfileCard(bioHtml) {
  const safeBio = DOMPurify.sanitize(bioHtml);

  return `<div class="profile-card" title="${DOMPurify.sanitize(bioHtml, { RETURN_DOM_FRAGMENT: false, RETURN_DOM: false, ALLOWED_TAGS: [] })}">${safeBio}</div>`;
}
```

Alternatively, use `textContent` to safely set the title:
```javascript
function renderProfileCard(bioHtml) {
  const safeBio = DOMPurify.sanitize(bioHtml);
  const card = document.createElement('div');
  card.className = 'profile-card';
  card.textContent = bioHtml; // textContent escapes all HTML
  card.innerHTML = safeBio;
  return card.outerHTML;
}
```

Or simplest: escape the attribute value with a helper:
```javascript
function htmlEscapeAttribute(str) {
  return str.replace(/["'&<>]/g, char => ({
    '"': '&quot;',
    "'": '&#39;',
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;'
  }[char]));
}

function renderProfileCard(bioHtml) {
  const safeBio = DOMPurify.sanitize(bioHtml);
  const escapedBio = htmlEscapeAttribute(safeBio);
  return `<div class="profile-card" title="${escapedBio}">${safeBio}</div>`;
}
```

## Explanation
DOMPurify.sanitize() by default sanitizes for HTML body context. When the sanitized output is placed in an HTML attribute (the `title` attribute), it is in a different parsing context. An attacker can craft input that passes body sanitization but exploits the attribute context to inject event handlers or break out of the attribute.

For example, input like `" onload="alert(1)"` could result in the sanitizer outputting content that, when placed in `title="${safeBio}"`, becomes `title="" onload="alert(1)"` — creating an executable event attribute.

The fix requires sanitizing the attribute value specifically for attribute context, or HTML-escaping the output before placing it into an attribute. The simplest approach is to HTML-escape the sanitized content when used in attribute values, ensuring characters like quotes cannot break out of the attribute boundary.
