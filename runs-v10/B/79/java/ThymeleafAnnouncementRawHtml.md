## Verdict

The finding is confirmed. Line 5 of `announcement-preview.html` uses `th:utext` to render untrusted data, which bypasses Thymeleaf's automatic escaping and allows Cross-Site Scripting (CWE-79). An attacker can inject malicious HTML and JavaScript through the announcement content.

## Source

The untrusted data originates from the `draftId` request parameter in `AnnouncementController.preview()`:

```
@GetMapping("/announcements/preview")
public String preview(@RequestParam String draftId, Model model) {
    model.addAttribute("announcement", service.loadDraft(draftId));
    return "announcement-preview";
}
```

The parameter is passed to `AnnouncementService.loadDraft()`, which retrieves an `AnnouncementDraft` object. This object's `bodyHtml` field contains untrusted content that flows directly into the template rendering sink.

The data reaches the sink in `announcement-preview.html` at line 5:
```
<section class="announcement-body" th:utext="${announcement.bodyHtml}"></section>
```

## Fix

Replace line 5 in `announcement-preview.html`:

**Before (vulnerable):**
```html
<section class="announcement-body" th:utext="${announcement.bodyHtml}"></section>
```

**After (fixed):**
```html
<section class="announcement-body" th:text="${announcement.bodyHtml}"></section>
```

Change `th:utext` to `th:text`. The `th:text` attribute applies Thymeleaf's automatic HTML entity encoding, escaping characters like `<`, `>`, `&`, and quotes so they are rendered as text rather than interpreted as HTML or JavaScript.

## Explanation

The vulnerability exists because `th:utext` (unescaped text) explicitly disables Thymeleaf's default escaping mechanism. This allows an attacker to inject HTML and JavaScript payloads that execute in the victim's browser. By switching to `th:text`, Thymeleaf will automatically encode all special characters, neutralizing the injection attack.

The fix relies on Thymeleaf's built-in output encoding, which is context-appropriate for HTML body content. This matches the Java-specific CWE-79 guidance: "Thymeleaf already escapes `th:text`, so the fix there is deleting `th:utext`." The change closes the vulnerability by making context-aware output encoding the default rather than an opt-in choice.

## Behaviour changes

**Content rendering**: HTML tags and special characters in `announcement.bodyHtml` will now be escaped and displayed as literal text rather than interpreted as markup. For example:
- Input: `<p>Draft body</p>` renders as: `&lt;p&gt;Draft body&lt;/p&gt;` (displayed as text `<p>Draft body</p>` in the browser)
- Input: `<img src=x onerror="alert('XSS')">` renders as escaped text, not an executable image tag

**Legitimate content**: If the application legitimately needs to render formatted HTML content (such as Markdown converted to HTML or rich text from a trusted editor), this fix will break that functionality. In such cases, the proper remediation requires:
1. Validating and sanitizing HTML input using a library like OWASP HTML Sanitizer before storage/display
2. Or restricting the content to a safe subset via an allowlist of permitted tags and attributes

For this evaluation case, the fix assumes the application should display announcement content as plain text, with no HTML rendering. If formatted content is required, a sanitization step must be added in the service layer before the data reaches the template.
