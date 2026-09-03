## Verdict

Cross-site scripting (XSS) vulnerability confirmed. User-controlled comment text is interpolated into HTML response without escaping, allowing injection of arbitrary JavaScript.

## Source

The vulnerability originates in the request handler chain:
1. User input enters via `req.body.comment` in feedbackController.js
2. Flows through feedbackService.js → notificationDispatcher.js as `rawComment`
3. Reaches digestEntryFormatter.js line 26 where it is directly embedded in HTML
4. Finally sent to client in digestPageRenderer.js line 13 via `res.send()`

## Fix

In digestEntryFormatter.js, escape the `rawComment` before interpolating it into HTML:

**Line 26 - change from:**
```javascript
const summaryHtml =
  `<li><strong>${safeAuthor}</strong> (${postedLabel}): ${entry.rawComment}</li>`;
```

**To:**
```javascript
const safeComment = escapeAuthorName(entry.rawComment);
const summaryHtml =
  `<li><strong>${safeAuthor}</strong> (${postedLabel}): ${safeComment}</li>`;
```

## Explanation

The code already defines `escapeAuthorName()` (lines 5-9) for HTML entity escaping. This function converts characters `&<>"'` to their HTML entity equivalents, preventing them from being interpreted as markup or script delimiters. 

The `authorName` field is correctly escaped on line 22, but `rawComment` is not. Applying the same escaping to `rawComment` neutralizes injected HTML and script tags by converting `<` to `&lt;`, `>` to `&gt;`, and quotes to their entity forms, ensuring the comment renders as text rather than executable code.
