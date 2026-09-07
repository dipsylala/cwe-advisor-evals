## Verdict

exploitable

## Source

`@RequestParam String draftId` in `AnnouncementController.preview()` accepts user input that is passed to `service.loadDraft(draftId)`. The `AnnouncementService.loadDraft()` method returns an `AnnouncementDraft` record whose `bodyHtml` field is then rendered in the template. Although hardcoded in this test case, the `draftId` parameter represents an attacker-controlled source that could influence the returned HTML content.

## Fix

**Vulnerable code (announcement-preview.html, line 5):**
```html
<section class="announcement-body" th:utext="${announcement.bodyHtml}"></section>
```

**Fixed code - Option 1: Sanitize HTML in Java (Recommended for markup fields)**

AnnouncementService.java:
```java
package cases.xss;

import com.googlecode.owasp.html.Sanitizers;
import com.googlecode.owasp.html.PolicyFactory;

public class AnnouncementService {
    public AnnouncementDraft loadDraft(String draftId) {
        String bodyHtml = "<p>Draft body</p>";
        
        // Sanitize HTML to prevent XSS while preserving legitimate markup
        PolicyFactory policy = Sanitizers.FORMATTING.and(Sanitizers.BLOCKS);
        String sanitizedHtml = policy.sanitize(bodyHtml);
        
        return new AnnouncementDraft("Maintenance", sanitizedHtml);
    }
}

record AnnouncementDraft(String title, String bodyHtml) {}
```

Template remains unchanged (keep `th:utext` since the HTML is now sanitized).

**Fixed code - Option 2: Escape output in template (Simpler but breaks markup rendering)**

announcement-preview.html, line 5:
```html
<section class="announcement-body" th:text="${announcement.bodyHtml}"></section>
```

## Explanation

The vulnerability exists because `th:utext` (unescaped text) in Thymeleaf renders HTML without escaping, allowing arbitrary HTML/JavaScript injection. The data flows from the user-controlled `draftId` parameter through `AnnouncementService.loadDraft()` to the `announcement.bodyHtml` field, which is then rendered unsafely in the template.

Since the field is explicitly named `bodyHtml`, it is intended to render HTML markup. The recommended fix is to sanitize the HTML in the Java code using OWASP Java HTML Sanitizer with an allowlist policy (Sanitizers.FORMATTING and Sanitizers.BLOCKS allow safe HTML formatting and block-level elements while removing script tags and event handlers), then keep `th:utext` to render the sanitized result. This preserves legitimate HTML markup while preventing XSS.

Alternatively, changing `th:utext` to `th:text` will escape all HTML tags as literal text, completely preventing XSS but silently breaking the intended functionality of rendering HTML markup.

## Behaviour changes

**Option 1 (Sanitization approach):**
- Adds a dependency on `com.googlecode.owasp-java-html-sanitizer:owasp-java-html-sanitizer` (version 20240325.1 or later as of the guidance timestamp)
- Modifies `AnnouncementService.loadDraft()` to sanitize the HTML before returning it
- The template rendering behavior remains unchanged - HTML is still rendered, but now restricted to safe elements and attributes
- Legitimate markup like `<p>`, `<strong>`, `<em>` will render correctly; script tags and event handlers will be stripped

**Option 2 (Template escape approach):**
- No dependency changes required
- Modifies only the template, changing `th:utext` to `th:text`
- Changes the rendered output: HTML markup will display as literal text (e.g., `<p>text</p>` renders as literal string, not as a paragraph)
- This is a functional regression if the intent is to render HTML markup

The guidance explicitly states that for fields named `bodyHtml` intended to carry markup, Option 1 (sanitization) is the proper approach to avoid silent functional regression.
