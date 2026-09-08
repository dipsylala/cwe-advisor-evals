## Verdict

exploitable

## Source

`rawBody`, the second parameter of `renderCommentBody(sanitizer, rawBody)` (`commentRenderer.js:1`) - a comment body, which is attacker-controlled user-submitted content. No validation, encoding, or sanitization is applied to it anywhere in the function before it reaches the sink.

## Fix

### File: commentRenderer.js

```javascript
const DOMPurify = require('dompurify');

function renderCommentBody(sanitizer, rawBody) {
  // SAST FINDING: CWE-79 (Cross-site Scripting) reported here. Sink is the next statement.
  const sanitizedBody = DOMPurify.sanitize(rawBody);
  return sanitizer.bypassSecurityTrustHtml(sanitizedBody);
}

module.exports = { renderCommentBody };
```

**Library recommendation:** DOMPurify, minimum safe version 3.4.0 (CVE-2026-41238 affects 3.0.1 through 3.3.3 under the plain `DOMPurify.sanitize(input)` call used here, and supersedes the earlier 3.2.4 floor associated with the `SAFE_FOR_TEMPLATES` bypass). No manifest file is part of this call chain; add `"dompurify": "^3.4.0"` to the project's `package.json` and confirm the resolved version with SCA/dependency-check tooling before merging.

## Explanation

`sanitizer.bypassSecurityTrustHtml()` is Angular's `DomSanitizer` escape hatch: it marks a string as pre-trusted `SafeHtml`, so Angular's own HTML sanitizer is skipped entirely when the result is later bound (typically via `[innerHTML]`). Calling it directly on `rawBody` means any HTML or script markup a commenter submits - `<img src=x onerror=...>`, an inline `<script>`, etc. - is rendered into the page verbatim and executes in every viewer's browser, which is a stored/persistent XSS. The fix does not remove the call to `bypassSecurityTrustHtml`, since that API exists precisely to let already-sanitized rich HTML through Angular's stricter default sanitizer; instead it sanitizes `rawBody` with `DOMPurify.sanitize()` first and passes only that return value into `bypassSecurityTrustHtml`. DOMPurify strips executable markup (script tags, event handler attributes, `javascript:` URIs, etc.) while preserving safe formatting tags, so the value being marked "trusted" has actually had the dangerous content neutralized before the trust bypass is asserted.

## Behaviour changes

- Added `DOMPurify.sanitize()` call on `rawBody` before it is passed to `bypassSecurityTrustHtml()`: this strips executable HTML/script content from the comment body. Legitimate formatting markup (e.g. `<b>`, `<i>`, `<a href="https://...">`) passes through unchanged; only dangerous constructs (script tags, event-handler attributes, `javascript:`/`data:` URIs, etc.) are removed. This is the only functional change and it is the fix itself, not a side effect.
- Return type is unchanged: the function still returns whatever `sanitizer.bypassSecurityTrustHtml()` produces (a `SafeHtml` value), so callers binding this to `[innerHTML]` or similar see no interface change.
- No other arguments, return paths, or error behavior were altered.

## Assumptions

- The single-file call chain gives no visibility into how `renderCommentBody`'s return value is consumed downstream (e.g. the template binding). The fix preserves the original return type (`SafeHtml` from `bypassSecurityTrustHtml`) rather than switching to `sanitizer.sanitize(SecurityContext.HTML, ...)`, on the assumption that the caller relies on receiving a pre-trusted `SafeHtml` value, consistent with why `bypassSecurityTrustHtml` was used in the first place (to preserve rich formatting Angular's default sanitizer would strip). Confidence: medium.
- `dompurify` is not currently a project dependency in this call chain (no `package.json` was provided); confirm it is added and its version resolved via SCA tooling as noted above.

## Verification

Copied the fixed file to a scratch directory (outside the repository) and ran `node --check` against it: syntax check passed with no diagnostics. `DOMPurify.sanitize` and `require('dompurify')` are the documented CommonJS entry point for the `dompurify` package (verified against its published API, not recalled); no other new names were introduced. No test harness or Angular build was reachable in this environment to exercise the binding at runtime.
