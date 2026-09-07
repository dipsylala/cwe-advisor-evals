## Verdict

**Confirmed real vulnerability.** Line 5 uses Thymeleaf's `th:utext` to render user-controlled HTML without escaping, allowing XSS injection.

## Source

The call chain:
1. `AnnouncementController.preview()` receives user-controlled `draftId` parameter
2. Passes it to `AnnouncementService.loadDraft(draftId)` which returns an `AnnouncementDraft` object
3. The `bodyHtml` field is bound to the template model
4. Template at line 5 renders it with `th:utext="${announcement.bodyHtml}"` (unescaped)

An attacker can inject malicious HTML/JavaScript: if `bodyHtml` contains `<script>alert('XSS')</script>`, it executes in the browser.

## Fix

### File: templates/announcement-preview.html

```html
<!doctype html>
<html lang="en">
<body>
  <h1 th:text="${announcement.title}">Title</h1>
  <section class="announcement-body" th:text="${announcement.bodyHtml}"></section>
</body>
</html>
```

## Explanation

Changed `th:utext` to `th:text` on line 5. Thymeleaf's `th:text` attribute automatically escapes HTML special characters (`<`, `>`, `&`, `"`, `'`) to their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`). This prevents HTML/JavaScript injection while still rendering the content as readable text. Any HTML tags become visible as text rather than executable code.
