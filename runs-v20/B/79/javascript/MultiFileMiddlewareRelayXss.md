## Verdict

Exploitable.

- **cwe_id**: CWE-79 (Improper Neutralization of Input During Web Page Generation, Cross-Site Scripting)
- **location**: `digestPageRenderer.js:13` (`res.send(...)` sink); root cause at `digestEntryFormatter.js:26` (`summaryHtml` template)
- **confidence**: high
- **library_recommendation**: none required - fix is a code-level output-encoding change using the escaping helper already present in the codebase.

## Source

`req.body.comment`, read in `feedbackController.js:17` (`handleFeedbackSubmission`), is attacker-controlled and passed through with no length limit and no encoding (unlike `authorName` on the line above, which is truncated with `.slice(0, 80)` but still not HTML-encoded at that point).

Call chain:

1. `feedbackController.js:17-21` - `comment` is read from the POST body and wrapped into a `FeedbackSubmission`, then passed to `feedbackService.submitFeedback(submission, res)`.
2. `feedbackService.js:23` - `submitFeedback` forwards it unchanged as `this.dispatcher.queueForDigest(recordId, submission.authorName, submission.comment, res)`.
3. `notificationDispatcher.js:11-23` - `queueForDigest` stores it on `entry.rawComment` and calls `this.formatter.formatEntry(entry, res)`.
4. `digestEntryFormatter.js:21-29` - `formatEntry` escapes `entry.authorName` via `escapeAuthorName()` but interpolates `entry.rawComment` **unescaped** directly into the `summaryHtml` template literal (`formatEntry`, line 26), then passes `summaryHtml` to `this.renderer.renderDigestPage(...)`.
5. `digestPageRenderer.js:4-13` - `renderDigestPage` embeds the already-built `summaryHtml` into `pageBody` and writes the full document with `res.send(...)` (the reported sink, line 13), with no encoding applied at any point downstream.

`authorName` is correctly HTML-encoded before use, which confirms the gap is specific to `comment`/`rawComment` rather than an oversight in the renderer itself - the renderer only ever receives an already-assembled HTML string and has no way to encode a sub-value after the fact. The break has to happen where `rawComment` is placed into the template, i.e. `digestEntryFormatter.js`.

An attacker submitting `POST /feedback` with `comment` containing `<script>...</script>` or an event-handler payload (e.g. `<img src=x onerror=...>`) gets it stored verbatim and reflected into the HTML digest page served via `res.send()`, executing in the browser of anyone who views the digest. This is a stored/reflected XSS in an HTML-body context.

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

The vulnerability is missing context-appropriate output encoding at the point where untrusted `comment` text is concatenated into an HTML string, not a flaw in the `res.send()` sink itself - `res.send()` faithfully sends whatever HTML it is given, exactly as it already does (correctly) for the encoded `authorName` value. The fix HTML-encodes `entry.rawComment` before interpolation, using the same character-class escaping routine the file already applies to `authorName` (`&`, `<`, `>`, `"`, `'`), so both interpolated values entering the `<li>` HTML-body context are neutralized consistently. The helper function is renamed from `escapeAuthorName` to `escapeHtml` because it is now applied to two different fields; its implementation and behavior for any given string are unchanged, so `authorName` encoding is unaffected. No other file needed to change: `digestPageRenderer.js` only ever receives a pre-built HTML string and has no independent access to the raw comment, so encoding could not correctly happen there.

## Behaviour changes

- `entry.rawComment` is now HTML-encoded before being placed in the rendered digest page, so comments containing `<`, `>`, `&`, `"`, or `'` render as literal escaped text instead of raw markup. This is the fix itself, not a side effect - legitimate comments containing those characters (e.g. `"great job!" & thanks <3`) will now display their literal characters correctly and safely, whereas previously any such characters were emitted as live, unencoded HTML (already broken for `<`/`&`, and exploitable for markup/scripts).
- `escapeAuthorName` was renamed to `escapeHtml`. Its only caller within this file is updated accordingly; the function is not exported or referenced from any other file in the call chain, so no other file requires a change.
- No change to function signatures, return values, arguments passed to `this.renderer.renderDigestPage(...)`, or any other file in the chain (`feedbackController.js`, `feedbackService.js`, `notificationDispatcher.js`, `digestPageRenderer.js`).

**Verification**: `node --check digestEntryFormatter.js` run against the fixed file in isolation - passed with no syntax errors. Manual trace confirmed `escapeHtml` is defined once and its only call sites are the two lines inside `formatEntry`; no other file references `escapeAuthorName` by name, so the rename is safe.
