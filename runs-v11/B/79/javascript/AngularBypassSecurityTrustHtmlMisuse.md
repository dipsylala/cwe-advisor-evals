## Verdict

Exploitable. The untrusted `rawBody` parameter flows directly to `DomSanitizer.bypassSecurityTrustHtml()` on line 3 without any sanitization or encoding, allowing arbitrary script injection.

## Source

Line 1: `rawBody` parameter in function `renderCommentBody(sanitizer, rawBody)` - untrusted user-supplied comment data from an external source.

## Fix

**Vulnerable code:**
```javascript
function renderCommentBody(sanitizer, rawBody) {
  // SAST FINDING: CWE-79 (Cross-site Scripting) reported here. Sink is the next statement.
  return sanitizer.bypassSecurityTrustHtml(rawBody);
}
```

**Fixed code:**
```javascript
function renderCommentBody(sanitizer, rawBody) {
  // Sanitize untrusted HTML with DOMPurify before marking as safe for Angular
  const sanitized = DOMPurify.sanitize(rawBody);
  return sanitizer.bypassSecurityTrustHtml(sanitized);
}
```

**Library recommendation:** DOMPurify version 3.4.0 or later. This version is the operative floor that closes CVE-2026-41238 affecting earlier versions under the `DOMPurify.sanitize(input)` call. Ensure the dependency is added to `package.json` and imported in the component.

## Explanation

The fix neutralizes the XSS vulnerability by sanitizing untrusted HTML with DOMPurify before marking it as safe for Angular's rendering. DOMPurify removes executable scripts and event handlers while preserving safe HTML structure and formatting. The sanitized output is then passed to `bypassSecurityTrustHtml()`, which is now safe to use because the HTML has been cleaned of injection payloads. This follows the guidance principle: never pass untrusted data directly through security bypass APIs; sanitize first, then mark as safe. The function maintains its contract of returning a `SafeHtml` object suitable for Angular's `[innerHTML]` binding.

## Behaviour changes

None. The function's return type and contract remain identical (`SafeHtml`). The only change is that `rawBody` is now sanitized before reaching the sink, preventing XSS injection while preserving legitimate HTML content rendering.
