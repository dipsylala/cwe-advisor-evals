## Verdict

Confirmed. `renderCommentBody` calls `DomSanitizer.bypassSecurityTrustHtml()` on `rawBody`, an attacker-controlled comment body. `bypassSecurityTrustHtml` does not sanitize its input - it marks the string as pre-approved "trusted" HTML, telling Angular to skip its normal DOM sanitizer entirely. Whatever markup is in the comment (e.g. `<img src=x onerror=alert(1)>`, `<script>`, event-handler attributes) is emitted verbatim into the page when the returned `SafeHtml` is later bound with `[innerHTML]`, giving stored XSS for any user who views the comment.

## Source

`rawBody`, the raw comment body text passed into `renderCommentBody(sanitizer, rawBody)`. This is attacker-controlled content (a user-submitted comment) flowing directly into the sink with no encoding or sanitization applied.

## Fix

### File: commentRenderer.js

```javascript
const { SecurityContext } = require('@angular/core');

function renderCommentBody(sanitizer, rawBody) {
  // Run the value through Angular's built-in sanitizer instead of bypassing it.
  // sanitizer.sanitize() strips dangerous markup/attributes (script tags, event
  // handlers, javascript: URLs, etc.) while still allowing safe formatting HTML
  // to render, so legitimate rich-text comments are preserved and hostile ones
  // are neutralized.
  return sanitizer.sanitize(SecurityContext.HTML, rawBody);
}

module.exports = { renderCommentBody };
```

## Explanation

`DomSanitizer.bypassSecurityTrustHtml()` exists for exactly one case: content the application itself constructed and knows to be safe (e.g. a static template fragment), never for values that originate from another user. Calling it on `rawBody` converts Angular's sanitizer from a safety net into a no-op for this code path - the returned `SafeHtml` is trusted unconditionally downstream, so any `<script>`, `onerror`, `onload`, or `javascript:` payload a commenter submits is rendered and executed in every other viewer's session (stored XSS).

The fix replaces the bypass with `sanitizer.sanitize(SecurityContext.HTML, rawBody)`. This is the same `DomSanitizer` service already injected into the function - no new dependency is introduced - but instead of marking the value trusted, it runs Angular's default HTML sanitizer (which strips unsafe elements, attributes, and URL schemes while keeping benign formatting markup like `<b>`, `<i>`, and `<a href="https://...">`) and returns a plain sanitized string. Because the value is no longer wrapped as "bypassed", any consumer that binds it via `[innerHTML]` gets Angular's normal protection, and no matter how this function's output is later used, it can never re-introduce raw attacker HTML into the DOM.

If the comment body is only ever expected to be plain text (no formatting at all), an equally valid alternative is to drop HTML rendering entirely and bind the raw string via Angular's default text interpolation (`{{ rawBody }}`) instead of `[innerHTML]`, since interpolation auto-escapes and needs no sanitizer call. The `sanitize()` fix above is preferred here because it preserves the original intent of rendering the value as HTML while closing the injection.
