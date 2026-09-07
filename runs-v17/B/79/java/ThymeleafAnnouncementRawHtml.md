## Verdict

Exploitable. The `th:utext` directive on line 5 renders untrusted HTML content without sanitization. An attacker controlling the `bodyHtml` value can inject malicious scripts that execute in the victim's browser.

## Source

`draftId` parameter from `@RequestParam` in AnnouncementController.preview() → service.loadDraft(draftId) → AnnouncementDraft.bodyHtml field

## Fix

### File: AnnouncementService.java

```java
package cases.xss;

import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

public class AnnouncementService {
    private static final PolicyFactory SANITIZER = Sanitizers.FORMATTING.and(Sanitizers.BLOCKS);

    public AnnouncementDraft loadDraft(String draftId) {
        String rawHtml = "<p>Draft body</p>";
        String sanitizedHtml = SANITIZER.sanitize(rawHtml);
        return new AnnouncementDraft("Maintenance", sanitizedHtml);
    }
}

record AnnouncementDraft(String title, String bodyHtml) {}
```

### File: templates/announcement-preview.html

```html
<!doctype html>
<html lang="en">
<body>
  <h1 th:text="${announcement.title}">Title</h1>
  <section class="announcement-body" th:utext="${announcement.bodyHtml}"></section>
</body>
</html>
```

## Explanation

The fix sanitizes the HTML content in AnnouncementService using OWASP Java HTML Sanitizer with a `PolicyFactory` that allows formatting and block-level tags while removing any malicious scripts, attributes, or dangerous constructs. The sanitizer is applied before the content is passed to the template. The template continues to use `th:utext` to render the sanitized HTML as markup (not as escaped text), which preserves the intended functionality of displaying HTML while eliminating the XSS vulnerability. Since the content is now verified as safe, the utext output is secure.

## Behaviour changes

**Dependency added**: The fix introduces a dependency on `com.googlecode.owasp-java-html-sanitizer:owasp-java-html-sanitizer`. Per the CWE-79 Java guidance, this is a maintained library (date-versioned; version `20240325.1` or later is required). The project build system must add this dependency.

**Content transformation**: The sanitizer removes any HTML tags and attributes not in its allowlist policy (`Sanitizers.FORMATTING.and(Sanitizers.BLOCKS)`). This means:
- Safe tags like `<p>`, `<br>`, `<strong>`, `<em>` are preserved
- Dangerous tags like `<script>`, `<img onerror>`, `<svg onload>` are removed
- On-handler attributes are removed
- This is necessary to close the XSS weakness; benign content containing only formatting and block tags is unaffected

No other behaviour changes. The template rendering contract (th:utext outputs HTML) and the return type (AnnouncementDraft) remain identical.

