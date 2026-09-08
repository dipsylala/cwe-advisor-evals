## Verdict

**Confirmed XSS (CWE-79)**: The `rawComment` user input flows unescaped from request body through the call chain to `res.send()` in digestPageRenderer.js, allowing attackers to inject arbitrary HTML and JavaScript.

## Source

User-submitted comment from HTTP request body (`req.body.comment` in feedbackController.js) passed through FeedbackService → NotificationDispatcher → DigestEntryFormatter → DigestPageRenderer as `rawComment`, then directly interpolated into an HTML template without encoding.

## Fix

### File: digestEntryFormatter.js

```javascript
'use strict';

const { DigestPageRenderer } = require('./digestPageRenderer');

function escapeHtml(text) {
  return String(text).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[ch]);
}

function relativeTime(timestampMs) {
  const minutes = Math.max(0, Math.round((Date.now() - timestampMs) / 60000));
  return minutes <= 1 ? 'just now' : `${minutes} min ago`;
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

The vulnerability occurs because `entry.rawComment` is interpolated directly into the HTML template at line 26 of the original file without any encoding. The `authorName` is escaped via `escapeAuthorName()`, but the comment is not, leaving an XSS injection point.

The fix renames `escapeAuthorName()` to the more generic `escapeHtml()` to clarify its purpose: HTML context encoding. This single function is applied to both `authorName` and `rawComment` before they are interpolated into the HTML template. HTML encoding converts special characters (`&`, `<`, `>`, `"`, `'`) to entity references, preventing interpretation of the data as code. This ensures that comment content containing `<script>`, event handlers like `onclick=`, or other HTML metacharacters are rendered as literal text rather than executable markup.

## Behaviour changes

- Comments containing HTML metacharacters (`<`, `>`, `&`, `"`, `'`) are now displayed as escaped entities in the rendered page, preventing XSS execution
- The visual display changes only for content with these characters; normal text renders identically
- Legitimate comment content with special characters (e.g., "John & Jane", "cost < $100") displays the escaped form to the user, matching standard web application behavior for untrusted content
- No change to response structure, headers, or functional behavior
