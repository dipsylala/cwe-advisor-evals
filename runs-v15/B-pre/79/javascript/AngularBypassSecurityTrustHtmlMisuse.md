## Verdict

VULNERABLE

## Source

```javascript
function renderCommentBody(sanitizer, rawBody) {
  // SAST FINDING: CWE-79 (Cross-site Scripting) reported here. Sink is the next statement.
  return sanitizer.bypassSecurityTrustHtml(rawBody);
}
```

The `bypassSecurityTrustHtml()` method is explicitly listed in CWE-79's taint sinks. It signals an Angular security bypass, meaning the developer is assuming the input is safe and has taken responsibility for that guarantee. No such guarantee exists here: `rawBody` is untrusted user input, and passing it directly to a bypass sink allows script injection.

## Fix

```javascript
const DOMPurify = require('dompurify');

function renderCommentBody(sanitizer, rawBody) {
  // Sanitize the HTML to remove any executable content
  const sanitizedHtml = DOMPurify.sanitize(rawBody);
  // Now it is safe to tell Angular to trust the sanitized result
  return sanitizer.bypassSecurityTrustHtml(sanitizedHtml);
}
```

**Setup note:** This fix requires DOMPurify 3.4.0 or later (the floor version that fixes CVE-2026-41238, which affects versions 3.0.1 through 3.3.3 under the plain `DOMPurify.sanitize()` call).

## Explanation

The key principle from CWE-79's guidance is: "Never pass untrusted data through a template or framework auto-escaping bypass." Angular's `bypassSecurityTrustHtml()` is one such bypass—it tells Angular to skip all safety checks. The vulnerability occurs because the method is invoked without ensuring the input has been sanitized first.

The fix inserts an explicit sanitization step using DOMPurify before invoking the bypass. DOMPurify removes executable script tags, event handlers, and other XSS payloads while preserving legitimate HTML markup. Only the sanitized (and therefore safe) result is passed to `bypassSecurityTrustHtml()`, making the developer's assumption that the input is safe actually true.

This follows the prescribed pattern: "Sanitize user-generated HTML with `DOMPurify.sanitize()` and assign only its return value to `innerHTML`"—applied here to the trust bypass instead of direct DOM insertion.

## Behaviour changes

- User input containing HTML tags is no longer executed as scripts. For example, `<img src=x onerror="alert('xss')">` is stripped to `<img src="x">` (onerror removed) or removed entirely depending on DOMPurify's configuration.
- Legitimate HTML markup (e.g., `<b>`, `<i>`, `<a>`) is preserved by DOMPurify's default configuration.
- Comments containing backticks, quotes, and ampersands render as literal characters instead of breaking out of the current parsing context.
- Performance impact: DOMPurify's parsing adds a small latency cost per sanitization, typically milliseconds for typical comment lengths.
