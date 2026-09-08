## Verdict

Confirmed. Reflected/stored cross-site scripting: the feedback comment submitted in the POST /feedback request body is written into the digest page's HTML with no encoding, so an attacker-supplied comment containing markup (e.g. `<script>...</script>` or an `onerror` handler) executes in the browser of anyone who views the resulting digest response.

## Source

`req.body.comment` in `feedbackController.js` (`handleFeedbackSubmission`) is read unescaped and carried as-is through the call chain:

- `feedbackController.js`: `comment` -> `FeedbackSubmission.comment`
- `feedbackService.js`: `submission.comment` -> `dispatcher.queueForDigest(recordId, submission.authorName, submission.comment, res)`
- `notificationDispatcher.js`: parameter `rawComment` -> stored as `entry.rawComment` -> `formatter.formatEntry(entry, res)`
- `digestEntryFormatter.js`: `formatEntry` builds `summaryHtml` and interpolates `entry.rawComment` **without escaping** (only `entry.authorName` is escaped, via `escapeAuthorName`)
- `digestPageRenderer.js` line 13: `res.send(...)` writes the assembled HTML, containing the unescaped comment, directly to the response — this is the sink the scanner flagged.

The vulnerability is introduced at the point `summaryHtml` is built in `digestEntryFormatter.js`, one file upstream of the reported sink line; the sink itself has no way to distinguish safe from unsafe markup once it has already been concatenated in.

## Fix

### File: digestEntryFormatter.js
```javascript
'use strict';

const { DigestPageRenderer } = require('./digestPageRenderer');

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({
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

`entry.authorName` was already passed through an HTML-escaping helper before being interpolated, but `entry.rawComment` — the field name itself signals untrusted, unprocessed input — was concatenated into `summaryHtml` verbatim. Since `summaryHtml` is later embedded whole into the page body and written to the response with `res.send()`, any HTML or script markup in the submitted comment is parsed and executed by the viewing browser rather than displayed as text.

The fix generalizes the existing escaping function (renamed `escapeHtml` since it now serves both fields) and applies it to `entry.rawComment` at the same point `entry.authorName` is escaped — immediately before the value is concatenated into the HTML string, in `digestEntryFormatter.js`. This is the correct place to fix the issue: it is where a plain string first becomes part of an HTML document, and it keeps the encoding co-located with the other field that undergoes the same treatment rather than duplicating escaping logic at the sink in `digestPageRenderer.js` or trying to sanitize further upstream where the value is not yet known to be destined for HTML output. No other file needs to change: `feedbackController.js`, `feedbackService.js`, and `notificationDispatcher.js` correctly treat the comment as an opaque string and only `digestEntryFormatter.js` assembles HTML from it, and `digestPageRenderer.js`'s `res.send()` continues to receive a string that is now fully HTML-safe by the time it reaches that sink.
