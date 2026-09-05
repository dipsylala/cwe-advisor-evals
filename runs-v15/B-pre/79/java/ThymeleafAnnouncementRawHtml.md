## Verdict

Exploitable. The template uses `th:utext` to render untrusted HTML without escaping. While the current service returns hardcoded safe content, the draftId parameter is user-controlled and could load drafts containing attacker-supplied HTML via the database or external source. The unescaped rendering would result in stored or reflected XSS execution.

## Source

The vulnerability chain:

1. **Entry point**: `AnnouncementController.preview()` accepts user-supplied `draftId` via `@RequestParam String draftId`
2. **Data flow**: `draftId` → `AnnouncementService.loadDraft(draftId)` → returns `AnnouncementDraft` with `bodyHtml` field
3. **Sink**: `announcement-preview.html` line 5 uses `th:utext="${announcement.bodyHtml}"` to render the HTML without escaping

The field `bodyHtml` is an explicit indicator that HTML markup is intended to be stored and rendered, but there is no validation or sanitization of its content before rendering.

## Fix

**Java side (AnnouncementService.java)** - Add sanitization using OWASP Java HTML Sanitizer:

```java
package cases.xss;

import com.googlecode.owasp.html.Sanitizers;
import com.googlecode.owasp.html.PolicyFactory;

public class AnnouncementService {
    private static final PolicyFactory POLICY = 
        Sanitizers.FORMATTING.and(Sanitizers.BLOCKS);

    public AnnouncementDraft loadDraft(String draftId) {
        String rawHtml = "<p>Draft body</p>";
        String sanitizedHtml = POLICY.sanitize(rawHtml);
        return new AnnouncementDraft("Maintenance", sanitizedHtml);
    }
}

record AnnouncementDraft(String title, String bodyHtml) {}
```

**Template side (announcement-preview.html)** - Keep `th:utext` since the HTML is now sanitized:

The template remains:
```html
<section class="announcement-body" th:utext="${announcement.bodyHtml}"></section>
```

No change is needed in the template once the Java code sanitizes the content.

**Dependency** - Add to `pom.xml`:

```xml
<dependency>
    <groupId>com.googlecode.owasp-java-html-sanitizer</groupId>
    <artifactId>owasp-java-html-sanitizer</artifactId>
    <version>20240325.1</version>
</dependency>
```

## Explanation

The vulnerability occurs because `th:utext` in Thymeleaf explicitly bypasses HTML escaping, treating its argument as trusted HTML content and rendering it directly into the page. Given that the field is named `bodyHtml`, the intent is clearly to support rich HTML content (like formatted paragraphs). Simply escaping this field with `th:text` would render the HTML tags as literal text, defeating the intended functionality.

The correct fix for fields meant to carry HTML markup is to sanitize the content using an allowlist-based HTML sanitizer. The OWASP Java HTML Sanitizer provides a `PolicyFactory` that defines which HTML tags and attributes are safe. The `Sanitizers.FORMATTING.and(Sanitizers.BLOCKS)` policy permits formatting tags (like `<b>`, `<i>`, `<p>`) and block-level elements while stripping any event handlers, script tags, or other attack vectors. This allows legitimate HTML to render while preventing XSS payloads such as `<img src=x onerror='alert(1)'>` from executing.

The sanitization is applied once in the service layer when loading the draft, ensuring all `bodyHtml` values are safe before they reach any template. The `th:utext` directive remains unchanged because the content is now guaranteed to be safe.

## Behaviour changes

1. **HTML sanitization policy applied**: The `bodyHtml` field is now constrained to a safe subset of HTML tags. Any tags outside the `FORMATTING` and `BLOCKS` policy (such as `<script>`, `<iframe>`, event handlers) will be removed from the output. Legitimate content like `<p>`, `<br>`, `<b>`, `<i>` will pass through unchanged.

2. **Dependency added**: The application now requires `owasp-java-html-sanitizer` version 20240325.1 or later. This dependency must be verified through SCA/dependency-check tooling before merging.

3. **No functional regression for safe content**: If all current `bodyHtml` values contain only permitted tags (as in the hardcoded `<p>Draft body</p>` example), there is no visible change in rendered output.

4. **Silent stripping of disallowed tags**: If future drafts contain tags outside the allowlist, those tags will be silently removed. This is safe behavior—the text content remains visible but the unsafe markup is discarded.

5. **No changes to controller or template**: The controller and template files require no modifications. The fix is entirely in the service layer, preserving the existing API contract while adding the security layer.
