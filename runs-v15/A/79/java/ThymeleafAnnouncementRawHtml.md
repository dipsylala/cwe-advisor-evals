## Verdict

CWE-79 (Cross-site Scripting) confirmed. The template renders announcement body content without escaping, allowing injection of arbitrary HTML and JavaScript.

## Source

`AnnouncementController.preview()` accepts a `draftId` request parameter and loads an announcement via `AnnouncementService.loadDraft()`, passing the result to the template model. The `announcement.bodyHtml` field contains HTML content provided to the application.

## Fix

Change line 5 in `templates/announcement-preview.html` from:
```html
  <section class="announcement-body" th:utext="${announcement.bodyHtml}"></section>
```

to:
```html
  <section class="announcement-body" th:text="${announcement.bodyHtml}"></section>
```

Replace `th:utext` with `th:text`. The `th:text` attribute escapes HTML special characters, preventing script injection while still displaying the content safely. If the application genuinely requires rendering rich HTML content, sanitize the input using a library like OWASP ESAPI or JSoup before storing it in the model.

## Explanation

Thymeleaf's `th:utext` (unescaped text) renders content as raw HTML without any escaping. This is dangerous when the content originates from user input or can be influenced by attacker-controlled parameters. The `draftId` request parameter can be manipulated to load different announcements; if any of those announcements contain JavaScript payloads (e.g., `<img src=x onerror="alert('xss')">`), they will execute in the victim's browser.

Switching to `th:text` escapes HTML metacharacters (`<`, `>`, `&`, etc.) to their entity equivalents (`&lt;`, `&gt;`, `&amp;`), rendering them as literal text. This prevents the browser from interpreting injected scripts while preserving the intended content display.
