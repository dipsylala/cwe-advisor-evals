## Verdict

exploitable

## Source

`rawBody` parameter passed to `renderCommentBody()` - untrusted user input representing comment content that may contain HTML

## Fix

### File: commentRenderer.js

```javascript
const DOMPurify = require('dompurify');

function renderCommentBody(sanitizer, rawBody) {
  // Sanitize the HTML first to remove any malicious scripts
  const sanitizedHtml = DOMPurify.sanitize(rawBody);
  // Then mark as safe for Angular to render
  return sanitizer.bypassSecurityTrustHtml(sanitizedHtml);
}

module.exports = { renderCommentBody };
```

**Library Recommendation:** DOMPurify 3.4.0 or later. This version and all subsequent versions are required because CVE-2026-41238 affects DOMPurify 3.0.1 through 3.3.3 under the plain `DOMPurify.sanitize(input)` call with no special configuration.

## Explanation

The original code passes untrusted user input (`rawBody`) directly to Angular's `bypassSecurityTrustHtml()`, which deliberately bypasses all security checks and renders the content as-is. An attacker can inject malicious JavaScript through HTML tags like `<img onerror="alert(1)">` or `<svg onload="...">`, which will execute in users' browsers. The fix sanitizes the input using DOMPurify before passing it to `bypassSecurityTrustHtml()`. DOMPurify removes all dangerous elements and event handlers while preserving legitimate HTML formatting. The `bypassSecurityTrustHtml()` call then safely marks the cleaned HTML as trusted for Angular's rendering, since the content has been vetted and threat-free.

## Behaviour changes

**New dependency added:** DOMPurify must be installed (version 3.4.0 or later). This introduces an external package dependency.

**Intermediate transformation:** The original input `rawBody` is now passed through `DOMPurify.sanitize()` before being used, producing `sanitizedHtml`. Dangerous markup like event handlers and script tags are removed by DOMPurify; only safe HTML structure remains. This may alter the appearance of specially crafted payloads but has no impact on legitimate comment content containing standard formatting.

**Return value unchanged:** The function still returns a `SafeHtml` object from `bypassSecurityTrustHtml()` with identical type, so Angular template bindings receive the same contract as before.
