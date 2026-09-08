## Verdict

CONFIRMED: CWE-79 (Cross-Site Scripting) vulnerability in Thymeleaf template using `th:utext` with untrusted HTML content.

## Source

The vulnerability originates from `AnnouncementDraft.bodyHtml` - a field named to suggest HTML markup content. The controller accepts `draftId` from `@RequestParam` (untrusted user input) and loads an announcement draft. While the hardcoded test data contains safe HTML (`<p>Draft body</p>`), the field is named and typed to contain user-controlled HTML markup that could be loaded from a database based on the untrusted `draftId`.

## Fix

The template file `announcement-preview.html` uses `th:utext` (unescaped text output) on line 5, which renders HTML markup without escaping. This is a documented escape opt-out sink that allows arbitrary HTML/JavaScript injection.

**Assumption**: The field is named `bodyHtml` to indicate it carries HTML markup (rich content), not because arbitrary untrusted HTML should be rendered unescaped. The proper remediation depends on whether the application actually needs to render HTML:

1. If HTML markup should NOT be rendered (text-only): Change `th:utext` to `th:text` to escape HTML entities
2. If HTML markup MUST be rendered: Sanitize in Java code with OWASP HTML Sanitizer before the template renders it

Given the context and the Thymeleaf guidance in the CWE-79 Java entry ("swapping `th:utext` for `th:text` closes the XSS"), the template-level fix is to replace the unescaped sink with the escaping variant.

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

The vulnerability is in the use of `th:utext="${announcement.bodyHtml}"` on line 5. The `th:utext` directive is Thymeleaf's unescaped text output - it renders the value as raw HTML without encoding or escaping. If `announcement.bodyHtml` contains untrusted data with malicious scripts (e.g., `<img onerror="alert('xss')">`), those scripts will execute in the victim's browser.

The fix replaces `th:utext` with `th:text`, which is Thymeleaf's escaping text output. This encodes HTML special characters (< becomes &lt;, > becomes &gt;, & becomes &amp;, etc.) so that markup tags are rendered as literal text instead of being interpreted as HTML elements. This prevents script injection.

The change aligns with CWE-79's core principle: "Apply context-specific encoding at every data sink" and with the Java-specific guidance that names `th:utext` as a documented escape opt-out sink requiring either sanitized input or use of `th:text` instead.

## Behaviour changes

**Functional impact**: HTML tags in the announcement body will now be displayed as literal text (e.g., `<p>Draft body</p>` displays as the string "<p>Draft body</p>" rather than a rendered paragraph). If the application intentionally supports rich HTML content (WYSIWYG editors, CMS body fields), this is a regression that must be accompanied by server-side HTML sanitization using the OWASP Java HTML Sanitizer and restoration of `th:utext` for the sanitized value.

**Security impact**: The change closes the XSS injection vector by ensuring all user-controlled content is treated as text data, not executable markup.

