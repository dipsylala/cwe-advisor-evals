## Verdict
exploitable

## Source
Untrusted user input from `req.body.comment` in feedbackController.js line 17 flows through feedbackService and notificationDispatcher without validation, reaching digestEntryFormatter.js where it is embedded directly into HTML output without escaping.

## Fix

**Vulnerable Code** (digestEntryFormatter.js, lines 25-26):
```javascript
const summaryHtml =
  `<li><strong>${safeAuthor}</strong> (${postedLabel}): ${entry.rawComment}</li>`;
```

**Fixed Code** (digestEntryFormatter.js, lines 25-27):
```javascript
const safeComment = escapeAuthorName(entry.rawComment);
const summaryHtml =
  `<li><strong>${safeAuthor}</strong> (${postedLabel}): ${safeComment}</li>`;
```

## Explanation
The vulnerability occurs because `rawComment` is rendered directly into HTML body text without encoding, while the `authorName` is properly escaped using the `escapeAuthorName()` function. An attacker can inject arbitrary HTML and JavaScript by submitting a comment containing tags like `<script>alert('xss')</script>` or event handlers like `<img onerror="alert('xss')">`. The fix applies the same HTML entity escaping to the comment that is already applied to the author name, converting dangerous characters (`<`, `>`, `&`, `"`, `'`) into their safe HTML entity equivalents. This ensures the comment is treated as data, not executable code, and allows legitimate content containing these characters to render safely.

## Behaviour changes
None. The fix preserves the existing contract of the `summaryHtml` variable: it still produces a valid HTML list item string with the same structure and output format. The escaping function handles all necessary character replacements without altering the length or semantic meaning of the content, and the downstream consumers (renderDigestPage, res.send) continue to operate identically. No error cases are introduced, no return values change, and no arguments to external functions are modified.
