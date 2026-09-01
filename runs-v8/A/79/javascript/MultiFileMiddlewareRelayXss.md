## Verdict
The finding is correct. User-supplied comment data flows through the middleware chain unescaped and is rendered directly into an HTML response at the sink.

## Source
The vulnerability originates in `feedbackController.js` where `req.body.comment` is passed through without sanitization:
```
const comment = req.body.comment || '';
const submission = new FeedbackSubmission(authorName, comment, new Date());
feedbackService.submitFeedback(submission, res);
```

The comment data is then threaded through `feedbackService.submitFeedback()` → `notificationDispatcher.queueForDigest()` → `digestEntryFormatter.formatEntry()` where it is embedded into HTML.

## Fix
In `digestEntryFormatter.js`, apply HTML entity escaping to `entry.rawComment` before embedding it in the HTML string, using the same `escapeAuthorName()` function already present in the file:

```javascript
formatEntry(entry, res) {
  const safeAuthor = escapeAuthorName(entry.authorName);
  const safeComment = escapeAuthorName(entry.rawComment);  // Add this line
  const postedLabel = relativeTime(entry.queuedAt);

  const summaryHtml =
    `<li><strong>${safeAuthor}</strong> (${postedLabel}): ${safeComment}</li>`;  // Use safeComment

  this.renderer.renderDigestPage(entry.recordId, summaryHtml, res);
}
```

## Explanation
The code already demonstrates proper HTML escaping for the `authorName` field via the `escapeAuthorName()` function, which replaces dangerous characters (`&`, `<`, `>`, `"`, `'`) with their HTML entity equivalents. The `rawComment` field must be escaped using the same mechanism before inclusion in the HTML template. Without this escaping, an attacker can inject arbitrary HTML and JavaScript by submitting a comment containing tags like `<script>alert('xss')</script>` or event handlers like `<img src=x onerror="alert('xss')">`. The fix ensures both user-supplied fields receive identical protective treatment.
