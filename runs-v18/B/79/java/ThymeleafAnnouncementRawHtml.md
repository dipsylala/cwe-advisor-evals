## Verdict

Exploitable. The template uses `th:utext` to render the `announcement.bodyHtml` field without HTML escaping, allowing injection of malicious scripts if the HTML content originates from untrusted sources (user input, database, external API).

## Source

HTTP request parameter `draftId` (AnnouncementController.java, line 15) is passed to `service.loadDraft(draftId)`, which returns an `AnnouncementDraft` object containing user-influenced content in the `bodyHtml` field (AnnouncementService.java, line 5).

## Fix

The vulnerability is in the Java service layer. The `bodyHtml` field is intended to carry HTML markup, so it must be sanitized using the OWASP Java HTML Sanitizer before being passed to the template. The template should keep `th:utext` to render the sanitized HTML correctly.

### File: AnnouncementService.java

```java
package cases.xss;

import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

public class AnnouncementService {
    private static final PolicyFactory POLICY = Sanitizers.FORMATTING.and(Sanitizers.BLOCKS);

    public AnnouncementDraft loadDraft(String draftId) {
        String unsafeHtml = "<p>Draft body</p>";
        String sanitizedHtml = POLICY.sanitize(unsafeHtml);
        return new AnnouncementDraft("Maintenance", sanitizedHtml);
    }
}

record AnnouncementDraft(String title, String bodyHtml) {}
```

## Explanation

The fix sanitizes the HTML content using OWASP Java HTML Sanitizer's `Sanitizers.FORMATTING.and(Sanitizers.BLOCKS)` policy, which removes dangerous elements and attributes while preserving safe formatting and block-level HTML. The sanitized result is stored in the `bodyHtml` field and passed to the template. The template's use of `th:utext` is correct for sanitized markup—it renders the safe HTML without additional escaping. This prevents XSS attacks while preserving the intended functionality of displaying formatted announcement bodies.

## Behaviour changes

**Dependency addition**: OWASP Java HTML Sanitizer (`com.googlecode.owasp-java-html-sanitizer:owasp-java-html-sanitizer`) must be added to the project dependencies. Minimum safe version: `20240325.1` (or later; check vendor advisories for any known bypasses).

**HTML content transformation**: The fix applies an allowlist sanitization policy to HTML content before storage. Any HTML attributes or elements not on the allowlist (e.g., `onclick`, `script`, `style` with dangerous content) will be removed. Legitimate formatting tags like `<p>`, `<b>`, `<i>`, and `<a>` are preserved by the `FORMATTING` and `BLOCKS` sanitizers. This is the intended behaviour for preventing XSS while maintaining rich-text display.

**No sink contract change**: The `loadDraft()` method still returns an `AnnouncementDraft` with the same structure. The template's `th:utext` directive correctly renders the now-safe HTML. No callers of `loadDraft()` are affected beyond receiving sanitized rather than raw HTML.
