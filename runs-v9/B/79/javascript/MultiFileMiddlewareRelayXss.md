## Verdict

**exploitable** (confidence: high)

CWE-79 - Improper Neutralization of Input During Web Page Generation ('Cross-Site Scripting'). The sink at `digestPageRenderer.js:13` (`res.send()` built from a template literal) emits an HTML page that embeds an attacker-controlled comment body with no encoding anywhere on the path.

## Source

`req.body.comment` in `feedbackController.js` (`handleFeedbackSubmission`, line 17) - the raw HTTP request body of a `POST /feedback` request, fully attacker-controlled, with no length cap, validation, or encoding applied at any point.

Call chain:

1. `feedbackController.js:17-21` - `comment` is read from `req.body.comment` and placed unmodified into a `FeedbackSubmission`.
2. `feedbackService.js:23` - `submitFeedback` forwards `submission.comment` straight into `dispatcher.queueForDigest(...)`.
3. `notificationDispatcher.js:11-23` - `queueForDigest` stores it as `entry.rawComment` and passes the `entry` to `formatter.formatEntry(entry, res)`.
4. `digestEntryFormatter.js:21-29` - `formatEntry` HTML-escapes `entry.authorName` via `escapeAuthorName()`, but concatenates `entry.rawComment` into the `summaryHtml` template literal **unescaped** (line 26).
5. `digestPageRenderer.js:6-13` - `summaryHtml` is embedded into `pageBody`, which is embedded into the full HTML document and written to the client with `res.send()` (the reported sink, line 13).

The break is at step 4: `authorName` is neutralized before use, `rawComment` is not, and it reaches the sink inside an HTML body (`<li>...: ${entry.rawComment}</li>`) context.

Sink contract (`res.send()` in `digestPageRenderer.js`): returns/sends the given string as the HTTP response body with `Content-Type` inferred as HTML by Express; nothing is discarded; no arguments are left implicit; on error it throws synchronously as any string-building code would. The fix only needs to change what "the given string" contains before it reaches `res.send()` - the call itself does not change.

## Fix

No third-party library is required; the file already contains a same-shaped escaping helper (`escapeAuthorName`) that just needs to also cover the comment field. Per `cwe/79/javascript/INDEX.md`, this is plain-text-into-HTML-body encoding, not rich-HTML sanitization, so DOMPurify is not the applicable control here.

**Vulnerable code** (`digestEntryFormatter.js`):

```javascript
function escapeAuthorName(name) {
  return String(name).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[ch]);
}

  formatEntry(entry, res) {
    const safeAuthor = escapeAuthorName(entry.authorName);
    const postedLabel = relativeTime(entry.queuedAt);

    const summaryHtml =
      // VULNERABLE: entry.rawComment is attacker-controlled (req.body.comment)
      // and is concatenated into the HTML response with no encoding.
      `<li><strong>${safeAuthor}</strong> (${postedLabel}): ${entry.rawComment}</li>`;

    this.renderer.renderDigestPage(entry.recordId, summaryHtml, res);
  }
```

**Fixed code** (`digestEntryFormatter.js`):

```javascript
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[ch]);
}

  formatEntry(entry, res) {
    const safeAuthor = escapeHtml(entry.authorName);
    const safeComment = escapeHtml(entry.rawComment);
    const postedLabel = relativeTime(entry.queuedAt);

    const summaryHtml =
      `<li><strong>${safeAuthor}</strong> (${postedLabel}): ${safeComment}</li>`;

    this.renderer.renderDigestPage(entry.recordId, summaryHtml, res);
  }
```

(The helper is renamed from `escapeAuthorName` to `escapeHtml` since it now encodes two distinct fields; both call sites are updated accordingly. `digestPageRenderer.js` and every other file in the chain are unchanged - the break was isolated to this one formatting step.)

## Explanation

`entry.rawComment` reaches an HTML-body sink (`res.send()`, via `digestPageRenderer.renderDigestPage`) without ever being encoded, while the sibling `authorName` field on the same line was already being escaped - the fix closes that gap by routing the comment through the identical HTML-entity escape (`&`, `<`, `>`, `"`, `'`) before it is concatenated into `summaryHtml`. This neutralizes `<`, `>`, and `"`/`'` so a payload such as `<script>...</script>` or an `onerror=` attribute-breakout in the comment body renders as inert text instead of executing in the victim's browser, while ordinary comment text (including literal `<`, `&`, or quotes) still displays correctly. Encoding is applied once, at the point the value is placed into an HTML body context, consistent with the per-sink, context-aware encoding the CWE-79 guidance calls for; no other file on the call chain needed to change.

## Behaviour changes

None beyond closing the weakness. `res.send()` is still called with the same document shape and the same arguments count; only the *content* of `summaryHtml` differs for comments containing `&`, `<`, `>`, `"`, or `'`, which now render as their literal HTML-entity-escaped form instead of being interpreted as markup - this is the intended effect of the fix, not an incidental change. The `escapeAuthorName` -> `escapeHtml` rename is a same-behavior rename (identical implementation) required only because the one helper now serves two call sites; `authorName`'s escaped output is byte-for-byte unchanged. No return values, arguments to `res.send()`/`renderDigestPage()`/`queueForDigest()`, error behavior, or stored data (`FeedbackService.records`) are altered.
