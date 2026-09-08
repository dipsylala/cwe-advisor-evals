## Verdict
VULNERABLE. The `rawComment` field flows unsanitized through the entire call chain and is embedded directly into HTML in the rendered digest page.

## Source
User-supplied `comment` from `req.body.comment` in `feedbackController.js` line 17. It enters the system unescaped and is stored as `rawComment` through the dispatcher chain without sanitization.

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
    const safeComment = escapeAuthorName(entry.rawComment);
    const postedLabel = relativeTime(entry.queuedAt);

    const summaryHtml =
      `<li><strong>${safeAuthor}</strong> (${postedLabel}): ${safeComment}</li>`;

    this.renderer.renderDigestPage(entry.recordId, summaryHtml, res);
  }
}

module.exports = { DigestEntryFormatter };
```

## Explanation
The vulnerability was that `entry.rawComment` was directly embedded into the HTML template on line 26 without HTML entity escaping. An attacker could inject `<script>alert('xss')</script>` or other malicious HTML/JavaScript through the comment field.

The fix applies the existing `escapeAuthorName()` HTML entity escaping function to the comment value, storing the result in `safeComment`. This prevents any HTML metacharacters (`&`, `<`, `>`, `"`, `'`) from being interpreted as markup, converting them to their safe entity representations (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&#39;`). The sanitized value is then used in the HTML template instead of the raw input.
