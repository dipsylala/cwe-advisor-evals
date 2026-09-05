## Verdict

Exploitable

## Source

The `rawBody` parameter to `renderCommentBody()` is untrusted user input, passed directly to the Angular DomSanitizer bypass at line 3.

## Fix

**Vulnerable code:**
```javascript
function renderCommentBody(sanitizer, rawBody) {
  // SAST FINDING: CWE-79 (Cross-site Scripting) reported here. Sink is the next statement.
  return sanitizer.bypassSecurityTrustHtml(rawBody);  // XSS: rawBody passed untrusted to bypass
}
```

**Fixed code:**
```javascript
import DOMPurify from 'dompurify';

function renderCommentBody(sanitizer, rawBody) {
  const sanitized = DOMPurify.sanitize(rawBody);
  return sanitizer.bypassSecurityTrustHtml(sanitized);
}
```

## Explanation

Angular's `DomSanitizer.bypassSecurityTrustHtml()` deliberately disables security checks and must receive only trusted HTML. Passing untrusted user input directly to this sink allows attackers to inject arbitrary JavaScript that executes in victims' browsers. The fix sanitizes the user-supplied HTML with DOMPurify (minimum version 3.4.0 to avoid CVE-2026-41238) before passing the sanitized output to `bypassSecurityTrustHtml()`, ensuring only safe HTML entities remain. DOMPurify removes script tags, event handlers, and other XSS vectors while preserving legitimate HTML formatting suitable for comment display.

## Behaviour changes

**Added import statement:** `import DOMPurify from 'dompurify'` - required for the sanitization function and available via npm package dompurify.

**New variable assignment:** `const sanitized = DOMPurify.sanitize(rawBody)` - sanitization step that produces clean HTML from untrusted input.

**Return value change:** `bypassSecurityTrustHtml()` now receives sanitized HTML instead of raw input, but still returns the same DomSanitizer-trusted object type used by the caller.

Rationale: The function's contract (returning a trusted HTML object for Angular binding) is preserved, but the object now wraps safe HTML rather than potentially malicious content.
