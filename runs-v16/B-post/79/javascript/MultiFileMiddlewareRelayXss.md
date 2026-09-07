## Verdict

Exploitable. Untrusted user input from `req.body.comment` flows through the call chain without proper escaping and is rendered into HTML content via template literals, allowing arbitrary script injection.

## Source

Request handler `handleFeedbackSubmission` in feedbackController.js accepts user-controlled `comment` from `req.body.comment` with no validation. This value is passed through `FeedbackService.submitFeedback()` → `NotificationDispatcher.queueForDigest()` → `DigestEntryFormatter.formatEntry()` where it remains unescaped as `entry.rawComment`.

## Fix

In `digestEntryFormatter.js`, escape the comment before embedding it in HTML:

**Vulnerable code (line 25-26):**
```javascript
const summaryHtml =
  `<li><strong>${safeAuthor}</strong> (${postedLabel}): ${entry.rawComment}</li>`;
```

**Fixed code:**
```javascript
const safeComment = escapeAuthorName(entry.rawComment);
const summaryHtml =
  `<li><strong>${safeAuthor}</strong> (${postedLabel}): ${safeComment}</li>`;
```

The existing `escapeAuthorName()` function (lines 5-9) performs complete HTML entity encoding of `&`, `<`, `>`, `"`, and `'` characters, which is appropriate for HTML body context. Apply this same escaping to the comment before inserting it into the template literal.

## Explanation

The vulnerability exists because `entry.rawComment` is a direct alias for the unvalidated `comment` parameter from the request body. It is embedded into HTML markup via template literal without entity encoding, allowing an attacker to inject arbitrary HTML and JavaScript. The fix escapes HTML special characters in the comment using the existing `escapeAuthorName()` function, which converts characters such as `<` to `&lt;`, preventing the browser from interpreting injected markup as code. The author name is already properly escaped in line 22; the same escaping must be applied to the comment on line 25 to close the vulnerability.

## Behaviour changes

None. The fix converts the untrusted `entry.rawComment` value to its safely-encoded equivalent and uses only the encoded value. The HTML output preserves the original comment text but renders special characters as entities, preventing script execution. No arguments, return values, or downstream dependencies are altered.
