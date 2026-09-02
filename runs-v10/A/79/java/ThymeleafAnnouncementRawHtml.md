## Verdict

Confirmed: CWE-79 Cross-site Scripting (XSS) vulnerability via unescaped HTML rendering in Thymeleaf template.

## Source

**AnnouncementController.java (lines 14-18):**
User-supplied `draftId` parameter passed to `service.loadDraft()` which returns an `AnnouncementDraft` object with `bodyHtml` field.

**AnnouncementService.java (lines 4-5):**
The service returns an `AnnouncementDraft` record containing `bodyHtml`. In a real application, this value would be loaded from a database based on user input and is therefore untrusted.

**announcement-preview.html (line 5):**
The `bodyHtml` is rendered using Thymeleaf's `th:utext` attribute, which outputs raw HTML without escaping.

## Fix

Change line 5 in `announcement-preview.html` from:
```html
<section class="announcement-body" th:utext="${announcement.bodyHtml}"></section>
```

To:
```html
<section class="announcement-body" th:text="${announcement.bodyHtml}"></section>
```

Replace `th:utext` (unescaped text) with `th:text` (escaped text).

## Explanation

The `th:utext` processor renders content as raw HTML without escaping special characters. When `bodyHtml` originates from user input or untrusted sources (as it does here via the `draftId` parameter leading to a database lookup), an attacker can inject arbitrary HTML and JavaScript.

For example, a malicious `bodyHtml` value like `<img src=x onerror="alert('XSS')">` or `<script>alert('XSS')</script>` would execute in the browser.

The `th:text` processor escapes HTML entities (`<`, `>`, `&`, `"`, `'`) before rendering, preventing script injection. Characters are converted to their HTML entity equivalents (e.g., `<` becomes `&lt;`), rendering them as literal text rather than executable markup.

If rendering legitimate HTML is a functional requirement, the `bodyHtml` value must be validated, sanitized, or generated only by trusted server-side code—never from user input. In this case, using `th:text` is the appropriate fix because it treats the content as plain text rather than HTML.
