## Verdict
Confirmed. Untrusted user input flows from HTTP request body to HTML response without escaping.

## Source
User input originates in `feedbackController.js` from `req.body.comment` (line 17) and flows untouched as `entry.rawComment` through the call chain: `feedbackService.js` → `notificationDispatcher.js` → `digestEntryFormatter.js` → `digestPageRenderer.js` line 13, where it's rendered in the HTML response without escaping.

## Fix
In `digestEntryFormatter.js`, escape `entry.rawComment` before inserting it into HTML, mirroring the existing `escapeAuthorName` treatment applied to `entry.authorName`:

```javascript
function escapeHtml(text) {
  return String(text).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[ch]);
}

class DigestEntryFormatter {
  constructor(renderer = new DigestPageRenderer()) {
    this.renderer = renderer;
  }

  formatEntry(entry, res) {
    const safeAuthor = escapeHtml(entry.authorName);
    const safeComment = escapeHtml(entry.rawComment);
    const postedLabel = relativeTime(entry.queuedAt);

    const summaryHtml =
      `<li><strong>${safeAuthor}</strong> (${postedLabel}): ${safeComment}</li>`;

    this.renderer.renderDigestPage(entry.recordId, summaryHtml, res);
  }
}

module.exports = { DigestEntryFormatter };
```

## Explanation
The vulnerability allows XSS because `entry.rawComment` is untrusted user input that reaches the HTML sink without escaping. An attacker supplying `<img src=x onerror=alert('xss')>` in the comment field causes malicious script execution. The fix HTML-escapes the comment (and generalizes the escape function to cover all user-supplied content) before inserting it into the HTML markup, preventing script interpretation while preserving the comment text.
