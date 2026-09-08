## Verdict
VULNERABLE - The template uses Thymeleaf's `th:utext` to render user-supplied HTML without escaping, allowing XSS injection.

## Source
The vulnerability originates from `AnnouncementController.preview()`, which accepts a `draftId` request parameter and passes it to `AnnouncementService.loadDraft()`. The service returns an `AnnouncementDraft` object with a `bodyHtml` field containing potentially unsafe HTML content. This untrusted content flows to the Thymeleaf template where it is rendered.

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
The vulnerability is on line 5 where `th:utext` renders the `announcement.bodyHtml` field as unescaped HTML. The `th:utext` attribute bypasses Thymeleaf's default HTML escaping, allowing any HTML/JavaScript in the value to execute in the browser context.

The fix changes `th:utext` to `th:text`. Thymeleaf's `th:text` attribute automatically escapes HTML special characters (converting `<` to `&lt;`, `>` to `&gt;`, etc.), which neutralizes any script tags or event handlers an attacker might inject. This prevents XSS while maintaining the template's functionality for rendering plain text announcements.

If the application legitimately requires rendering trusted HTML content (e.g., from a WYSIWYG editor), the proper remediation would require sanitizing the HTML on the server side using a library like OWASP HTML Sanitizer before storing or rendering it, followed by the use of `th:utext`. However, for general-purpose announcement text, using `th:text` to escape all HTML is the safest and most appropriate fix.
