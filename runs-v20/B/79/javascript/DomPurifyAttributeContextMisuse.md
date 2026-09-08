## Verdict

Exploitable. CWE-79 (Cross-Site Scripting), confidence: high.

## Source

- **Source**: `bioHtml`, the parameter to `renderProfileCard(bioHtml)` in `profileCard.js`. This is attacker-influenced profile bio content (the function's only input, rendered into a page).
- **Sink**: line 7, the template literal `` `<div class="profile-card" title="${safeBio}">${safeBio}</div>` ``. `safeBio` (the output of `DOMPurify.sanitize(bioHtml)`) is interpolated into two different output contexts from a single sanitize call: the `title` HTML attribute value, and the element's text/HTML body content.
- **Sink contract** (`DOMPurify.sanitize`, called with no config object, so all defaults apply): returns a string safe to assign to an HTML **body** sink such as `innerHTML` - it strips disallowed tags/attributes and entity-encodes characters that are meaningful in HTML text content (`&`, `<`, `>`). It does **not** encode `"` or `'`, because quotes carry no special meaning inside HTML text content, only inside a quoted attribute value. It does not throw on malformed input; it returns a best-effort sanitized string.
- **The gap**: DOMPurify's documented threat model covers HTML-body re-insertion sinks only, and explicitly excludes reuse of its output inside an attribute value. Here the same `safeBio` returned for body-context use is reused unmodified for the `title="..."` attribute. Because `"` passes through `sanitize()` untouched, a bio value containing a literal `"` closes the `title` attribute early and lets the rest of the string be parsed as new, live HTML attributes on the same `<div>` (e.g. an `onmouseover` handler), independent of whatever tags `sanitize()` stripped.
- Verified empirically (Node 24, `dompurify` + `jsdom`): `DOMPurify.sanitize('John" onmouseover="alert(document.cookie)" x="')` returns the string unchanged (quotes intact). Interpolating that into the original line 7 template and re-parsing the resulting HTML with jsdom produces a `<div>` with four live attributes - `class`, `title`, `onmouseover`, and `x` - confirming the injected `onmouseover="alert(document.cookie)"` becomes a real, executing attribute, not just text.

## Fix

### File: profileCard.js
```javascript
const DOMPurify = require('dompurify');

function escapeHtmlAttribute(value) {
  return value.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function renderProfileCard(bioHtml) {
  const safeBio = DOMPurify.sanitize(bioHtml);

  // safeBio is sanitized for the HTML-body context; the title attribute needs
  // its own attribute-context escaping since DOMPurify does not encode quotes
  // in text output (they are safe in body text but break out of a quoted attribute).
  return `<div class="profile-card" title="${escapeHtmlAttribute(safeBio)}">${safeBio}</div>`;
}
```

## Explanation

`safeBio` is left exactly as `DOMPurify.sanitize()` returns it and continues to be used unmodified for the element body content, where it is a correct, safe value per DOMPurify's own threat model. A second value, produced by passing `safeBio` through a small `escapeHtmlAttribute` helper that encodes `"` to `&quot;` and `'` to `&#39;`, is used only for the `title` attribute. This closes the gap without re-encoding characters DOMPurify already handles for text content (`&`, `<`, `>`) - `sanitize()`'s output already renders those correctly in body text (verified: `sanitize('Tom & Jerry <3 cats')` returns `'Tom &amp; Jerry &lt;3 cats'`), so escaping them again in the attribute value would double-encode and visibly corrupt legitimate content (e.g. turning `&amp;` into `&amp;amp;`). Escaping only the quote characters is the minimal, context-correct fix: it neutralizes the one class of character that is inert in HTML text but breaks out of a double- or single-quoted attribute, while leaving everything DOMPurify already encoded untouched.

Verified with the same reproduction harness: rendering the same attack payload through the fixed function and re-parsing the result with jsdom shows the `<div>` now has exactly two attributes (`class`, `title`) - the injected `onmouseover` no longer materializes as a live attribute, and the full attack string is preserved as inert, literal attribute text. A legitimate bio (`'Loves <b>hiking</b> & coding'`) still sanitizes and renders correctly in the body; in the `title` attribute it appears as escaped literal text, which is the correct behavior for an attribute that cannot render markup regardless.

**Verification performed**: `node --check` on the fixed file (syntax OK). Functional test: loaded the fixed module under Node 24 with `dompurify` 3.x and `jsdom` providing the global `window` DOMPurify's factory expects (matching the original file's bare `require('dompurify')` usage pattern), called `renderProfileCard()` with the attribute-breakout payload above, and re-parsed the returned HTML string with `jsdom` to confirm no extra attribute is created on the `<div>` and the payload is preserved as inert text in `title`.

## Behaviour changes

- Added a new local helper function, `escapeHtmlAttribute`, not present in the original file. It is a pure string transform using only the JavaScript standard library (`String.prototype.replace` with regex literals); no new import or dependency.
- The `title` attribute's value now differs from the element body's content when the sanitized bio contains `"` or `'`: those characters render as `&quot;`/`&#39;` in the attribute (and are decoded back to literal `"`/`'` by the browser when read, e.g. via `element.title`), whereas the body content still shows the literal character. This is the intended, sole effect of the fix - it is required to remove the attribute-breakout path, and it does not change behavior for any bio that contains no quote characters.
- The element body content (`safeBio` used as the div's inner HTML) is untouched - same call, same value, same position in the template.
- No change to `DOMPurify.sanitize()`'s call or configuration, so its allowed-tags/attributes defaults, return value, and failure behavior for the body sink are all unchanged.
