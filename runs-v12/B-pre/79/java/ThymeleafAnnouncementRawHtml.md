## Verdict

CWE-79 (Cross-Site Scripting) confirmed in Thymeleaf template.

The vulnerability exists at line 5 of `announcement-preview.html` where `th:utext` disables output escaping for the `announcement.bodyHtml` attribute. The `th:utext` directive is a taint sink that renders content as raw HTML without any encoding or sanitization, allowing attackers to inject malicious scripts that execute in victim browsers.

## Source

User-controlled input flows from the `draftId` request parameter through `AnnouncementController.preview()` to `AnnouncementService.loadDraft()`, which retrieves an `AnnouncementDraft` object containing the `bodyHtml` field. In a real application, this field would be populated from user input or an untrusted data source (database, external API). The data is then passed to the Thymeleaf template model as `announcement.bodyHtml`.

## Fix

Replace `th:utext` with `th:text` on line 5 of `announcement-preview.html`:

**Vulnerable code (line 5):**
```
  <section class="announcement-body" th:utext="${announcement.bodyHtml}"></section>
```

**Fixed code:**
```
  <section class="announcement-body" th:text="${announcement.bodyHtml}"></section>
```

## Explanation

Thymeleaf's `th:text` attribute automatically applies HTML entity encoding to all values, preventing any embedded HTML or JavaScript from being interpreted as executable code. Changing from `th:utext` (which explicitly disables escaping) to `th:text` (which enables escaping by default) closes the XSS vulnerability.

The `th:utext` directive was treating the `bodyHtml` field as trusted server-controlled content and rendering it without encoding. By switching to `th:text`, all special characters in the content (`<`, `>`, `&`, quotes) are converted to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), ensuring that any untrusted input cannot break out of the text context to inject scripts or event handlers.

## Behaviour changes

**HTML rendering**: With `th:text`, any literal HTML markup in the `bodyHtml` field (such as `<p>` or `<strong>` tags) will be displayed as text rather than rendered as formatting. If the application requires rich HTML content with formatting, an alternative approach would be needed: either sanitize the HTML using a library such as OWASP HTML Sanitizer or jsoup before storing it in the database, or use a sandboxed iframe to isolate the content. However, the direct fix to close the XSS vulnerability is to replace `th:utext` with `th:text`.

**Content display**: Users will see HTML markup as literal text (e.g., the string `<p>Draft body</p>` displays as `<p>Draft body</p>` instead of rendering as a paragraph). This is the safe default; if rich HTML is needed, implement proper input sanitization before rendering.
