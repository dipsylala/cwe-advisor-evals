## Verdict

Confirmed. `AnnouncementDraft.bodyHtml` is rendered with `th:utext`, which outputs the string as raw, unescaped HTML/JS. Any draft body that carries attacker-controlled markup (e.g. `<script>` or an `onerror` handler) executes in the browser of anyone who opens the preview.

## Source

- Request entry point: `AnnouncementController.preview(@RequestParam String draftId, Model model)` takes the attacker-influenced `draftId` and calls `service.loadDraft(draftId)`.
- `AnnouncementService.loadDraft(String draftId)` returns an `AnnouncementDraft` whose `bodyHtml` field is intended to hold saved announcement content (drafts are authored/edited by users of the announcement system, so `bodyHtml` is attacker-reachable even though this stub hardcodes a literal value).
- Sink: `templates/announcement-preview.html` line 5, `<section class="announcement-body" th:utext="${announcement.bodyHtml}"></section>`. Thymeleaf's `th:utext` performs no output encoding, so whatever is in `bodyHtml` is emitted verbatim into the page.

## Fix

### File: AnnouncementService.java

```java
package cases.xss;

import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

public class AnnouncementService {
    private static final PolicyFactory BODY_HTML_POLICY =
            Sanitizers.FORMATTING.and(Sanitizers.LINKS).and(Sanitizers.BLOCKS);

    public AnnouncementDraft loadDraft(String draftId) {
        String rawBodyHtml = "<p>Draft body</p>";
        return new AnnouncementDraft("Maintenance", BODY_HTML_POLICY.sanitize(rawBodyHtml));
    }
}

record AnnouncementDraft(String title, String bodyHtml) {}
```

## Explanation

The announcement body is meant to hold formatted, rich-text content (the template gives it its own `announcement-body` section rather than treating it as plain text), so the correct primary defense is not to switch the template to `th:text` and lose that feature - it is to constrain the HTML itself to a safe subset before it ever reaches the sink. `AnnouncementService.loadDraft` is the boundary where the announcement's HTML is produced/loaded, so sanitization belongs there: run the body through the OWASP Java HTML Sanitizer (`com.googlecode.owasp-java-html-sanitizer:owasp-java-html-sanitizer`) using a policy built from `Sanitizers.FORMATTING`, `Sanitizers.LINKS`, and `Sanitizers.BLOCKS` - this keeps ordinary formatting markup (bold, italics, paragraphs, lists, safe links) and strips `<script>`, inline event handlers (`onerror`, `onclick`, ...), `javascript:` URLs, and any other tag or attribute capable of running script, while leaving the template's `th:utext` render path untouched since the value it receives is now confined to a known-safe HTML subset. Keeping `th:utext` (rather than escaping everything with `th:text`) preserves the intended rendering behavior; the fix is constraining what can reach it, not disabling raw HTML output outright. Verify by feeding a payload such as `<img src=x onerror=alert(1)>` or `<script>alert(1)</script>` through `loadDraft`'s sanitizer and confirming the sanitized `bodyHtml` contains neither the script tag nor the `onerror` attribute, while a legitimate formatted draft (e.g. `<p><b>bold</b> and a <a href="https://example.com">link</a></p>`) passes through intact.
