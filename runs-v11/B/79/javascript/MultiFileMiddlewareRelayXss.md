## Verdict

Exploitable. Untrusted user input (`req.body.comment`) flows through the call chain without sanitization and is rendered as executable HTML/JavaScript in the browser response.

## Source

Untrusted data entry point: `req.body.comment` in `feedbackController.js` line 17. The comment value is passed through `FeedbackService.submitFeedback()` → `NotificationDispatcher.queueForDigest()` → `DigestEntryFormatter.formatEntry()` as `entry.rawComment`, where it is concatenated directly into HTML without escaping at line 26 of `digestEntryFormatter.js`.

The unescaped HTML is then passed to `DigestPageRenderer.renderDigestPage()` as `summaryHtml` and sent to the client via `res.send()` at line 13 of `digestPageRenderer.js`.

## Fix

**Vulnerable code in digestEntryFormatter.js (line 26):**
```javascript
const summaryHtml =
  `<li><strong>${safeAuthor}</strong> (${postedLabel}): ${entry.rawComment}</li>`;
```

**Fixed code in digestEntryFormatter.js:**
```javascript
const summaryHtml =
  `<li><strong>${safeAuthor}</strong> (${postedLabel}): ${escapeAuthorName(entry.rawComment)}</li>`;
```

Apply the existing `escapeAuthorName()` function (which performs HTML entity encoding) to `entry.rawComment` before concatenating it into the HTML string. This ensures that any special HTML characters in the user's comment are neutralized and cannot be interpreted as tags or script execution.

## Explanation

The vulnerability exists because `entry.rawComment` receives untrusted user input without any encoding or sanitization. While `entry.authorName` is properly escaped using `escapeAuthorName()` which converts HTML metacharacters (`&`, `<`, `>`, `"`, `'`) to their entity equivalents, the comment field bypasses this protection. Applying the same HTML entity encoding function to the comment ensures that any injected `<script>` tags, event handlers, or other XSS payloads are rendered as harmless text rather than executable code. This is context-appropriate encoding for the HTML body text context where the data is rendered.

## Behaviour changes

None. The `escapeAuthorName()` function performs standard HTML entity encoding and preserves the readability of legitimate content (converting `&` to `&amp;`, `<` to `&lt;`, etc.). The fix does not alter the function signature, return type, or any other aspect of the call chain—it only ensures untrusted data is properly neutralized before rendering.
