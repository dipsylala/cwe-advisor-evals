## Verdict

The finding is confirmed. User-supplied comment text flows from `req.body.comment` in feedbackController.js through the call chain without HTML encoding, reaches digestEntryFormatter.js where it is embedded in an HTML template literal, and arrives at the res.send() sink in digestPageRenderer.js. An attacker can inject arbitrary HTML and JavaScript into the rendered page.

## Source

**feedbackController.js, line 17**
```javascript
const comment = req.body.comment || '';
```

User input from the request body. No validation or encoding is applied here; the value is passed through as-is.

## Fix

**digestEntryFormatter.js, lines 5-26**

The primary defence layer is in digestEntryFormatter.js where the HTML is constructed. The `authorName` is properly escaped using the existing `escapeAuthorName()` function (line 22), but `rawComment` is inserted directly into the template literal without escaping (line 26).

**Vulnerable code:**
```javascript
function escapeAuthorName(name) {
  return String(name).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[ch]);
}

// ... later in formatEntry() ...

const summaryHtml =
  `<li><strong>${safeAuthor}</strong> (${postedLabel}): ${entry.rawComment}</li>`;
```

**Fixed code:**
```javascript
function escapeHtmlContent(text) {
  return String(text).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[ch]);
}

// ... later in formatEntry() ...

const safeAuthor = escapeHtmlContent(entry.authorName);
const safeComment = escapeHtmlContent(entry.rawComment);
const postedLabel = relativeTime(entry.queuedAt);

const summaryHtml =
  `<li><strong>${safeAuthor}</strong> (${postedLabel}): ${safeComment}</li>`;
```

The fix applies the same HTML entity encoding to both `authorName` and `rawComment` before inserting them into the HTML template. Both values originate from untrusted sources (authorName from feedbackController.js line 16, comment from line 17) and require encoding for their context (HTML body text).

## Explanation

The vulnerability occurs because user-supplied comment text is embedded directly into an HTML response without encoding. While `authorName` is encoded with `escapeAuthorName()`, the `rawComment` field bypasses this protection and is inserted as-is into the template literal. This allows an attacker to inject arbitrary HTML tags and JavaScript, which will execute in the victim's browser.

The fix introduces a single HTML escaping function that encodes the five dangerous characters (`&`, `<`, `>`, `"`, `'`) into their HTML entity equivalents. Both `authorName` and `rawComment` are escaped using this function before being embedded in the template literal. This ensures that any special characters in the comment are treated as data, not markup or script, preventing the injection.

The fix applies context-aware encoding at the data source—where the HTML string is constructed—rather than at the sink. This is the preferred approach because it ensures the value is safe regardless of how many times the template is used. The sink (res.send() in digestPageRenderer.js) remains unchanged and continues to work as before; it receives safe HTML that requires no further transformation.

## Behaviour changes

- All user-supplied content in the digest (both author name and comment text) will have HTML special characters converted to entities
- Comments containing `<`, `>`, `&`, `"`, or `'` characters will display those characters literally in the rendered page instead of being interpreted as HTML or script
- Legitimate text like "bread & butter" will render as "bread &amp; butter", "3 < 5" will render as "3 &lt; 5"
- No functional change to the application: the digest still renders correctly with the same layout and styling; user experience is unchanged for normal input
