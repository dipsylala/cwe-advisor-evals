## Verdict

Exploitable.

## Source

`bioHtml` parameter (untrusted user-supplied data).

## Fix

**Vulnerable Code:**
```javascript
function renderProfileCard(bioHtml) {
  const safeBio = DOMPurify.sanitize(bioHtml);

  // SAST FINDING: CWE-79 (Cross-site Scripting) reported here. Sink is the next statement.
  return `<div class="profile-card" title="${safeBio}">${safeBio}</div>`;
}
```

**Fixed Code:**
```javascript
function renderProfileCard(bioHtml) {
  const safeBio = DOMPurify.sanitize(bioHtml);

  // Escape bioHtml for use in HTML attribute context
  const bioAttribute = bioHtml
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  return `<div class="profile-card" title="${bioAttribute}">${safeBio}</div>`;
}
```

## Explanation

DOMPurify.sanitize() is designed for HTML body content context only. Per DOMPurify's threat model, its output is not safe for use in attributes, SVG, MathML, XML, or rawtext elements. The original code places sanitized HTML into the `title` attribute, which requires attribute-specific escaping. Attributes do not support HTML entities for structural content—they need character escaping to prevent attribute boundary breakout. The fix escapes the original input for attribute context by replacing `&`, `"`, `<`, and `>` with their corresponding HTML entities, while preserving DOMPurify sanitization for the HTML content sink.

## Behaviour changes

- The `title` attribute now receives HTML-escaped text instead of the HTML-sanitized output. Attribute values display entity sequences as their decoded characters (e.g., `&quot;` renders as `"`), which is the correct behavior for HTML attributes. This prevents attackers from breaking the attribute boundary with quotes or angle brackets.
- The HTML content body continues to use DOMPurify.sanitize() output unchanged, preserving rich HTML formatting for display.
- No changes to the return value contract or error behavior.
