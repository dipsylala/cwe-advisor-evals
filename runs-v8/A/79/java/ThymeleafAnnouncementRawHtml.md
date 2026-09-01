## Verdict

This is a confirmed Cross-Site Scripting (XSS) vulnerability. The Thymeleaf template uses `th:utext` to render user-controlled HTML content without any escaping or sanitization, allowing attackers to inject arbitrary JavaScript code.

## Source

**File:** `announcement-preview.html`, line 5

```html
<section class="announcement-body" th:utext="${announcement.bodyHtml}"></section>
```

The `bodyHtml` attribute originates from `AnnouncementService.loadDraft(draftId)`, which loads announcement data based on a request parameter `draftId`. In production, this data would be retrieved from a database based on user-supplied input, creating a potential vector for stored or reflected XSS attacks.

## Fix

Replace `th:utext` with `th:text`:

```html
<section class="announcement-body" th:text="${announcement.bodyHtml}"></section>
```

Alternatively, if HTML rendering is genuinely required, sanitize the content using a library such as OWASP HtmlSanitizer before passing it to the template.

## Explanation

The vulnerability exists because `th:utext` (Thymeleaf's "unescaped text" directive) renders the value directly as HTML without escaping special characters. An attacker who can control the `bodyHtml` value can inject malicious script tags (e.g., `<script>alert('XSS')</script>`) that execute in the victim's browser.

By switching to `th:text`, Thymeleaf automatically escapes HTML metacharacters (`<`, `>`, `&`, etc.), converting them to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`). This prevents script tags and other HTML constructs from being interpreted as code while still displaying the intended content safely to the user.

If the application genuinely needs to render HTML content (e.g., formatted announcements with intentional markup), the HTML must first be sanitized by a library that whitelists safe tags and removes or neutralizes event handlers and dangerous attributes.
