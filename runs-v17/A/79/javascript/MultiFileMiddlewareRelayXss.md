## Verdict
CONFIRMED. The unescaped user-supplied `rawComment` is embedded directly into HTML and reaches the response sink at line 13 of digestPageRenderer.js without sanitization.

## Source
The vulnerability originates in `feedbackController.js` where user input (`req.body.comment`) flows as `rawComment` through `FeedbackService` → `NotificationDispatcher` → `DigestEntryFormatter` → `DigestPageRenderer`.

In `digestEntryFormatter.js` line 26, the `entry.rawComment` is embedded directly into an HTML string without escaping: ``const summaryHtml = `<li><strong>${safeAuthor}</strong> (${postedLabel}): ${entry.rawComment}</li>`;``

This unsanitized HTML is then passed to `digestPageRenderer.js` where it is embedded into the final response at line 13.

An attacker can inject malicious JavaScript by sending a comment like `<img src=x onerror="alert('XSS')">` which will execute in the browser of anyone viewing the digest.

## Fix

### File: digestEntryFormatter.js
```javascript
'use strict';

const { DigestPageRenderer } = require('./digestPageRenderer');

function escapeAuthorName(name) {
  return String(name).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[ch]);
}

function escapeHtmlContent(content) {
  return String(content).replace(/[&<>"']/g, (ch) => ({
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
    const safeAuthor = escapeAuthorName(entry.authorName);
    const safeComment = escapeHtmlContent(entry.rawComment);
    const postedLabel = relativeTime(entry.queuedAt);

    const summaryHtml =
      `<li><strong>${safeAuthor}</strong> (${postedLabel}): ${safeComment}</li>`;

    this.renderer.renderDigestPage(entry.recordId, summaryHtml, res);
  }
}

module.exports = { DigestEntryFormatter };
```

## Explanation
The vulnerability is a classic reflected XSS where untrusted user input is rendered directly into HTML without encoding special characters. The fix escapes all five HTML special characters (`&`, `<`, `>`, `"`, `'`) in user-supplied content using standard HTML entity encoding.

The escaping is applied in `digestEntryFormatter.js` at the point where user-controlled `rawComment` is embedded into HTML markup. This is the correct location because it is the closest point to the source where we know the data is being used in an HTML context. By escaping here, we prevent malicious payloads from being interpreted as code regardless of how the HTML is later rendered or composed.

The fix uses the same character-to-entity mapping pattern already established in the codebase for `escapeAuthorName()`, ensuring consistency and maintainability. All special characters that have meaning in HTML markup are escaped, preventing injection of both script tags and event handlers.
