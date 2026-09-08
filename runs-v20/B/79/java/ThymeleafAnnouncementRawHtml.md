## Verdict

Exploitable. CWE-79 (stored/reflected Cross-Site Scripting) confirmed. `AnnouncementDraft.bodyHtml` reaches the response body through Thymeleaf's `th:utext`, which performs no output escaping, so any HTML/JavaScript contained in that field executes in the viewing browser. Confidence: high.

## Source

`AnnouncementController.preview(@RequestParam String draftId, Model model)` (`AnnouncementController.java`, line 15) takes the untrusted `draftId` request parameter and calls `service.loadDraft(draftId)`. That call returns an `AnnouncementDraft` record whose `bodyHtml` field is the announcement's rich-text body - content that, in a real deployment, was authored and persisted by whoever created the draft rather than validated at this read path. That value is placed into the view model unchanged (`model.addAttribute("announcement", ...)`).

That value flows unchanged to the sink: `templates/announcement-preview.html`, line 5, `<section class="announcement-body" th:utext="${announcement.bodyHtml}"></section>`. `th:utext` writes its expression result to the response with no HTML-entity escaping, unlike `th:text` on the `title` field one line above.

## Fix

### File: AnnouncementController.java

```java
package cases.xss;

import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

public class AnnouncementController {
    private static final PolicyFactory BODY_HTML_POLICY = Sanitizers.FORMATTING.and(Sanitizers.BLOCKS);

    private final AnnouncementService service;

    public AnnouncementController(AnnouncementService service) {
        this.service = service;
    }

    @GetMapping("/announcements/preview")
    public String preview(@RequestParam String draftId, Model model) {
        AnnouncementDraft draft = service.loadDraft(draftId);
        String safeBodyHtml = BODY_HTML_POLICY.sanitize(draft.bodyHtml());
        model.addAttribute("announcement", new AnnouncementDraft(draft.title(), safeBodyHtml));
        return "announcement-preview";
    }
}
```

## Explanation

`bodyHtml` is a rich-text field that is meant to carry markup (it already renders through `th:utext`, and the sample value is `<p>Draft body</p>"), so the correct defense is sanitization, not encoding: switching the template to `th:text` would print every tag as literal text and silently break legitimate announcements, while `Encode.forHtml()` would do the same. The fix instead runs the draft's `bodyHtml` through the OWASP Java HTML Sanitizer (`com.googlecode.owasp-java-html-sanitizer:owasp-java-html-sanitizer`, package `org.owasp.html`) using an explicit allowlist policy, `Sanitizers.FORMATTING.and(Sanitizers.BLOCKS)`, before it is placed on the model. That policy keeps ordinary formatting and block markup (paragraphs, headings, lists, bold/italic, line breaks) and strips everything else - `<script>`, event-handler attributes, `<iframe>`, inline `style`, `javascript:` URLs - so an attacker-controlled draft can no longer inject executable content, while the template keeps `th:utext` to render the now-safe HTML rather than losing the markup entirely. The `title` field is untouched: `th:text` already HTML-escapes it, so no separate encoding step is needed there. Because `AnnouncementDraft` is an immutable record, the fix builds a new instance carrying the sanitized body rather than mutating the one returned by the service, so `AnnouncementService` and its stubbed data are unchanged.

Given a specific dependency-version floor could not be confirmed against a vendor advisory in this pass, `20240325.1` (the release documented in the loaded guidance) should be checked against current SCA/dependency data before the manifest is pinned.

## Behaviour changes

- `announcement.bodyHtml` is now passed through `Sanitizers.FORMATTING.and(Sanitizers.BLOCKS)` before reaching the template. Reason: this is the fix itself - it removes script-capable and attribute-based injection vectors while preserving the field's intended formatting/block markup, so the existing `<p>Draft body</p>` sample is unaffected.
- Any markup outside that allowlist that a real draft might legitimately contain today (e.g. links via `<a href>`, images) would now be stripped along with the malicious content, since the fix currently allows only formatting and block-level tags. If announcements are expected to carry links or images, the policy should be widened with `Sanitizers.LINKS` and/or `Sanitizers.IMAGES` rather than treated as a functional regression to silently accept.
- No other arguments, return values, or control flow changed; `AnnouncementService.loadDraft` and the template are unmodified.

Verification: `AnnouncementController.java` was compiled together with the unmodified `AnnouncementService.java` using `javac`, in a scratch directory outside the case tree, against `owasp-java-html-sanitizer-20240325.1.jar`, `spring-web-6.1.14.jar`, `spring-core-6.1.14.jar`, `spring-beans-6.1.14.jar`, and `spring-context-6.1.14.jar` resolved from the local Maven cache. Compilation succeeded with no errors or warnings, confirming `PolicyFactory`, `Sanitizers.FORMATTING`, `Sanitizers.BLOCKS`, the package-private `AnnouncementDraft` record access, and the `Model`/`@GetMapping`/`@RequestParam` usages all resolve correctly.
