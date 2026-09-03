## Verdict
CONFIRMED. The template uses `th:utext` to render `announcement.bodyHtml` without escaping, creating an XSS vulnerability when the HTML content originates from user input or is constructed from unsanitized data.

## Source
**File**: `templates/announcement-preview.html`, line 5  
**Code**:
```html
<section class="announcement-body" th:utext="${announcement.bodyHtml}"></section>
```

The `th:utext` attribute in Thymeleaf renders the attribute value without HTML escaping. If `announcement.bodyHtml` contains or is derived from user-supplied input, an attacker can inject arbitrary JavaScript.

The vulnerability chain:
1. Controller accepts user input via `@RequestParam String draftId`
2. Service loads draft data (potentially based on untrusted input)
3. Template renders `bodyHtml` using `th:utext`, which does not escape HTML entities

## Fix
**Option 1: If HTML rendering is not needed** (simplest and most secure)  
Replace `th:utext` with `th:text` in the template:
```html
<section class="announcement-body" th:text="${announcement.bodyHtml}"></section>
```

**Option 2: If HTML rendering is required**  
Sanitize the HTML in the Java service before storing or rendering it. Add a sanitization library (e.g., jsoup) and clean the content:

In `AnnouncementService.java`:
```java
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;

public class AnnouncementService {
    public AnnouncementDraft loadDraft(String draftId) {
        String rawHtml = "<p>Draft body</p>"; // or fetch from untrusted source
        String cleanHtml = Jsoup.clean(rawHtml, Safelist.basic());
        return new AnnouncementDraft("Maintenance", cleanHtml);
    }
}
```

Then use `th:utext` safely:
```html
<section class="announcement-body" th:utext="${announcement.bodyHtml}"></section>
```

## Explanation
`th:utext` bypasses Thymeleaf's automatic HTML escaping, which is necessary for rendering pre-escaped or sanitized content. However, if the content is untrusted or user-derived, it must be sanitized before rendering.

The recommended fix depends on intent: if `bodyHtml` should contain only plain text, switch to `th:text` for automatic escaping. If HTML markup is intentional, sanitize the input server-side using a library like jsoup with a restrictive `Safelist` (e.g., `Safelist.basic()`) to allow only safe HTML tags and remove scripts, event handlers, and dangerous attributes.

This prevents stored and reflected XSS attacks while preserving necessary HTML rendering functionality.
