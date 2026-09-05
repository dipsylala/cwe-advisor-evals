## Verdict

Confirmed. The vulnerability is exploitable.

## Source

`evals/cases/79/javascript/DomPurifyAttributeContextMisuse/profileCard.js:7`

Untrusted input `bioHtml` is passed to `DOMPurify.sanitize()` on line 4, producing `safeBio`. The sanitized result is then used as an HTML attribute value (`title="${safeBio}"`) on line 7, violating DOMPurify's stated threat model.

## Fix

Remove the `title` attribute from the returned HTML string. DOMPurify's threat model explicitly excludes attributes as a safe output context. The attribute should not contain user-generated HTML regardless of sanitization.

**Before:**
```javascript
return `<div class="profile-card" title="${safeBio}">${safeBio}</div>`;
```

**After:**
```javascript
return `<div class="profile-card">${safeBio}</div>`;
```

## Explanation

DOMPurify is designed to sanitize HTML for re-insertion into HTML body contexts only. Its documentation explicitly states its threat model excludes attributes, SVG, MathML, XML, and rawtext elements. The code violates this by placing the sanitized HTML output into the `title` attribute.

While the `safeBio` on the right (body content) is correctly placed in an HTML body context where DOMPurify operates, its use in the attribute context on the left undermines the safety guarantees. Attributes require different encoding semantics than HTML body elements, and DOMPurify does not provide this encoding.

The fix removes the problematic attribute entirely. If an attribute is needed for metadata, it should contain plain text extracted from the HTML (not the HTML structure itself) and properly encoded for attribute context—or it should be populated from a controlled source rather than untrusted input.

## Behaviour changes

- The `title` attribute (browser tooltip) is removed from the rendered profile card div
- Only the HTML body content is rendered, preventing attribute-context XSS
- No change to the visual presentation of the bio content itself; only the hover tooltip is removed
