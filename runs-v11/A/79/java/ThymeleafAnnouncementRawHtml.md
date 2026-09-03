## Verdict
Confirmed XSS vulnerability via unescaped HTML rendering in Thymeleaf template.

## Source
User-controlled input enters through the `@RequestParam String draftId` in `AnnouncementController.preview()`, flows through `AnnouncementService.loadDraft()` which returns an `AnnouncementDraft` object with a `bodyHtml` field.

## Fix
Replace `th:utext` with `th:text` on line 5 of `announcement-preview.html`:

**Before:**
```html
<section class="announcement-body" th:utext="${announcement.bodyHtml}"></section>
```

**After:**
```html
<section class="announcement-body" th:text="${announcement.bodyHtml}"></section>
```

## Explanation
The vulnerability stems from Thymeleaf's `th:utext` directive, which renders text without HTML escaping. This allows injected script tags or event handlers within `announcement.bodyHtml` to execute in the browser. The fix uses `th:text` instead, which escapes all HTML special characters (converting `<` to `&lt;`, `>` to `&gt;`, etc.), preventing the browser from interpreting the content as executable code. This is the primary defense for output-based XSS in templating engines. If legitimate HTML rendering is required (e.g., for rich text from an editor), a separate HTML sanitization step using a library like jsoup or HtmlSanitizer should be introduced upstream in the service layer before the data reaches the template.
