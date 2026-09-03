## Verdict

exploitable

## Source

The `draftId` parameter from the HTTP request (line 15 in `AnnouncementController.preview()` method marked with `@RequestParam String draftId`) is untrusted user input. It flows through `service.loadDraft(draftId)` to populate an `AnnouncementDraft` object, whose `bodyHtml` field is then passed to the template for rendering.

## Fix

**Vulnerable code (line 5):**
```
<section class="announcement-body" th:utext="${announcement.bodyHtml}"></section>
```

**Fixed code:**
```
<section class="announcement-body" th:text="${announcement.bodyHtml}"></section>
```

## Explanation

The `th:utext` directive renders HTML without escaping, allowing any malicious scripts in the `announcement.bodyHtml` value to execute in the browser. Replacing `th:utext` with `th:text` causes Thymeleaf to automatically escape the content, converting HTML special characters and tags to their entity-encoded equivalents (`<` → `&lt;`, `>` → `&gt;`, etc.), which prevents script execution while preserving the text content. According to the CWE-79 Java guidance: "Thymeleaf already escapes `th:text`, so the fix there is deleting `th:utext`" when the field does not require literal HTML rendering.

## Behaviour changes

HTML markup in the `bodyHtml` field will now be displayed as literal text rather than rendered as formatted HTML. For example, `<p>Draft body</p>` will appear in the page as the literal string `<p>Draft body</p>` instead of as a paragraph element. If the application intentionally requires HTML rendering for this field, the appropriate mitigation would be to sanitize the `bodyHtml` value server-side using the OWASP Java HTML Sanitizer with an explicit `PolicyFactory` (e.g. `Sanitizers.FORMATTING.and(Sanitizers.BLOCKS)`) before passing it to the template, then keep the `th:utext` directive for the sanitized result.
