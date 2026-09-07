## Verdict

Exploitable.

## Source

The `rawBody` parameter received by `renderCommentBody()` is untrusted user-supplied comment text.

## Fix

**Vulnerable code:**

```javascript
function renderCommentBody(sanitizer, rawBody) {
  // SAST FINDING: CWE-79 (Cross-site Scripting) reported here. Sink is the next statement.
  return sanitizer.bypassSecurityTrustHtml(rawBody);  // Dangerous: bypasses all HTML sanitization
}
```

**Fixed code:**

```javascript
function renderCommentBody(sanitizer, rawBody) {
  const sanitized = DOMPurify.sanitize(rawBody);
  return sanitizer.bypassSecurityTrustHtml(sanitized);
}
```

Add DOMPurify to your dependencies: `npm install dompurify` (minimum version 3.4.0).

## Explanation

The vulnerability occurs because `bypassSecurityTrustHtml()` explicitly disables Angular's HTML sanitization without any prior validation. When untrusted user input (`rawBody`) is passed directly to this sink, any embedded JavaScript—such as `<img onerror="alert('xss')">` or `<svg onload="...">"`—will execute in the victim's browser when the function's result is rendered via Angular's `[innerHTML]` binding.

The fix sanitizes the input using DOMPurify before marking it as trusted HTML. DOMPurify removes script tags, event handlers, and other dangerous markup while preserving legitimate HTML structure. Version 3.4.0 or later is required to address CVE-2026-41238, which affected earlier versions under this exact usage pattern. After sanitization, the now-safe output is passed to `bypassSecurityTrustHtml()`, which wraps it for Angular's renderer without re-sanitizing—respecting DOMPurify's guidance that post-sanitization edits can void protection.

## Behaviour changes

- Added `const sanitized = DOMPurify.sanitize(rawBody);` statement: sanitizes untrusted input by removing script tags and dangerous event handlers. This is the required fix for the vulnerability.
- Changed argument to `bypassSecurityTrustHtml()` from `rawBody` to `sanitized`: ensures only verified-safe HTML bypasses Angular's protections, changing the function's security contract from "trust this blindly" to "trust this because we sanitized it first."
