## Verdict

Exploitable. User-controlled input from `req.body.comment` flows through the call chain without encoding and reaches the HTML rendering sink `res.send()` at digestPageRenderer.js line 13. An attacker can inject arbitrary HTML and JavaScript into the response.

## Source

`req.body.comment` from the POST request body in feedbackController.js line 17. This untrusted user input is passed through the call chain:
1. FeedbackSubmission constructor (feedbackController.js line 19)
2. feedbackService.submitFeedback() (feedbackController.js line 21)
3. dispatcher.queueForDigest() as rawComment parameter (feedbackService.js line 23)
4. entry.rawComment stored in notification dispatcher (notificationDispatcher.js line 15)
5. digestEntryFormatter.formatEntry() receives entry (notificationDispatcher.js line 22)
6. Embedded directly into HTML without encoding (digestEntryFormatter.js line 26)
7. Passed as summaryHtml to renderDigestPage (digestEntryFormatter.js line 28)
8. Rendered via res.send() (digestPageRenderer.js line 13)

## Fix

The vulnerability is that `entry.rawComment` is embedded directly into HTML at digestEntryFormatter.js line 26 without HTML entity encoding. The fix applies the existing `escapeAuthorName()` function to encode the raw comment before insertion into the HTML string.

### File: digestEntryFormatter.js

```javascript
'use strict';

const { DigestPageRenderer } = require('./digestPageRenderer');

function escapeAuthorName(name) {
  return String(name).replace(/[&<>"']/g, (ch) => ({
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
    const postedLabel = relativeTime(entry.queuedAt);

    const summaryHtml =
      `<li><strong>${safeAuthor}</strong> (${postedLabel}): ${escapeAuthorName(entry.rawComment)}</li>`;

    this.renderer.renderDigestPage(entry.recordId, summaryHtml, res);
  }
}

module.exports = { DigestEntryFormatter };
```

## Explanation

The fix applies HTML entity encoding to `entry.rawComment` before it is embedded into the HTML page template. The `escapeAuthorName()` function encodes the five characters that have special meaning in HTML context (`&`, `<`, `>`, `"`, `'`) by replacing them with their entity equivalents. This transforms any XSS payload in the comment (e.g., `<script>alert('xss')</script>`) into harmless text that will render literally in the browser rather than execute as code. The encoding is applied at the point where untrusted data enters the HTML string, following the CWE-79 guidance for context-specific output encoding.

## Behaviour changes

None. HTML entity encoding is transparent to legitimate content—special characters that should appear as text (e.g., `&`, `<`, `>`) are rendered correctly by the browser after decoding the entities, and the page layout remains unchanged.
