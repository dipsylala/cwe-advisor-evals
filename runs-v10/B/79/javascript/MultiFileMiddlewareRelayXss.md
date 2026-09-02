## Verdict

Confirmed. The vulnerability is exploitable. Untrusted user input from `req.body.comment` flows through the application without encoding and is rendered directly into HTML markup sent to the browser.

## Source

`req.body.comment` in `feedbackController.js` (line 17). This value is user-controlled POST body data, treated as untrusted throughout the application design but never encoded before rendering.

## Fix

In `digestEntryFormatter.js`, apply HTML encoding to `entry.rawComment` before embedding it in the template:

**Original code (digestEntryFormatter.js, lines 21-28):**
```javascript
  formatEntry(entry, res) {
    const safeAuthor = escapeAuthorName(entry.authorName);
    const postedLabel = relativeTime(entry.queuedAt);

    const summaryHtml =
      `<li><strong>${safeAuthor}</strong> (${postedLabel}): ${entry.rawComment}</li>`;

    this.renderer.renderDigestPage(entry.recordId, summaryHtml, res);
  }
```

**Fixed code:**
```javascript
  formatEntry(entry, res) {
    const safeAuthor = escapeAuthorName(entry.authorName);
    const safeComment = escapeAuthorName(entry.rawComment);
    const postedLabel = relativeTime(entry.queuedAt);

    const summaryHtml =
      `<li><strong>${safeAuthor}</strong> (${postedLabel}): ${safeComment}</li>`;

    this.renderer.renderDigestPage(entry.recordId, summaryHtml, res);
  }
```

## Explanation

The vulnerability exists because `entry.rawComment` (untrusted user input) is directly interpolated into HTML markup without encoding. Although the code demonstrates awareness of the risk by encoding `authorName` via `escapeAuthorName()`, the same encoding is not applied to the comment body.

The fix applies context-specific HTML entity encoding to the comment before rendering. This transforms dangerous characters (`<`, `>`, `&`, `"`, `'`) into their safe HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), ensuring the data is treated as text content rather than executable markup. The same `escapeAuthorName` function used for the author name is reused for the comment because both fields contain untrusted text that must be rendered as data, not code. The encoding happens at the output sink context (HTML body text), which is the correct location per CWE-79 guidance.

## Behaviour changes

- Comments containing HTML/XML metacharacters (`<`, `>`, `&`) or quotes will be displayed with their entities visible (e.g., a comment containing `<script>` will display as `&lt;script&gt;` in the rendered HTML).
- Malicious payloads such as `<img src=x onerror=alert(1)>` will be neutralized and displayed as literal text instead of executing.
- Legitimate comments with special characters (e.g., mathematical notation like `2 < 3`, or ampersands) will remain readable but will be entity-encoded in the HTML source.
- No change to the HTTP response headers, content type, or overall page structure; only the rendering of the comment text is affected.
