## Verdict

**Confirmed CWE-79 Cross-Site Scripting vulnerability.**

The untrusted user input from `req.body.comment` flows through the call chain and reaches the HTML output without escaping, allowing arbitrary JavaScript execution in the victim's browser.

## Source

User-supplied `comment` field from request body (`req.body.comment`) in `feedbackController.js`. This value is passed through:
1. `FeedbackSubmission` object
2. `FeedbackService.submitFeedback()`
3. `NotificationDispatcher.queueForDigest()` as `rawComment`
4. `DigestEntryFormatter.formatEntry()` where it is inserted into HTML at line 26

## Fix

In `digestEntryFormatter.js` line 26, apply HTML escaping to `entry.rawComment` before inserting it into the template:

```javascript
const summaryHtml =
  `<li><strong>${safeAuthor}</strong> (${postedLabel}): ${escapeAuthorName(entry.rawComment)}</li>`;
```

The existing `escapeAuthorName()` function (lines 5-8) properly escapes HTML metacharacters (`&`, `<`, `>`, `"`, `'`) and should be reused on the comment field to prevent injection.

## Explanation

The vulnerability exists because `entry.rawComment` is concatenated directly into HTML without HTML entity escaping. While `entry.authorName` is correctly escaped using `escapeAuthorName()` before insertion, the comment text receives no sanitization. An attacker can inject payloads like `<img src=x onerror="alert('xss')">` which will execute in the victim's browser when the HTML is rendered by `res.send()`.

The fix applies the same escaping strategy already used for the author name to the comment field, neutralizing all HTML metacharacters and preventing script injection while preserving the comment text content.
