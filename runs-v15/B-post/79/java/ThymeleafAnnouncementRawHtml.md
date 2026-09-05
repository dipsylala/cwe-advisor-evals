## Verdict

Exploitable. The template uses `th:utext` to render `announcement.bodyHtml` without sanitization. `th:utext` bypasses HTML escaping in Thymeleaf, so any HTML or JavaScript injected into `bodyHtml` will execute in the browser. While the test case hardcodes the content, in production this field would be populated from user input when announcements are created or edited, enabling XSS attacks.

## Source

**Location**: evals/cases/79/java/ThymeleafAnnouncementRawHtml/AnnouncementService.java

**Data source**: AnnouncementService.loadDraft() returns an AnnouncementDraft record with a `bodyHtml` field. In the test case this is hardcoded, but in a real application the bodyHtml would be populated from user input (e.g., a rich-text editor submission).

**Data flow**: 
1. AnnouncementController receives `draftId` request parameter
2. Calls `service.loadDraft(draftId)` which returns AnnouncementDraft
3. AnnouncementDraft contains `bodyHtml` field with user-controlled markup
4. Controller adds to model: `model.addAttribute("announcement", ...)`
5. Template accesses via EL expression: `${announcement.bodyHtml}`

## Fix

**Vulnerable code** (templates/announcement-preview.html, line 5):

```html
<section class="announcement-body" th:utext="${announcement.bodyHtml}"></section>
```

**Fixed code** (two approaches):

**Option 1: Sanitize in Java (recommended for this case)**

In AnnouncementService.java, apply OWASP Java HTML Sanitizer before returning:

```java
package cases.xss;

import com.googlecode.owasp.java_html_sanitizer.HtmlPolicyBuilder;
import com.googlecode.owasp.java_html_sanitizer.PolicyFactory;
import com.googlecode.owasp.java_html_sanitizer.Sanitizers;

public class AnnouncementService {
    private static final PolicyFactory POLICY = 
        Sanitizers.FORMATTING
            .and(Sanitizers.BLOCKS)
            .and(Sanitizers.LINKS);

    public AnnouncementDraft loadDraft(String draftId) {
        String unsanitizedHtml = "<p>Draft body</p>";
        String sanitizedHtml = POLICY.sanitize(unsanitizedHtml);
        return new AnnouncementDraft("Maintenance", sanitizedHtml);
    }
}

record AnnouncementDraft(String title, String bodyHtml) {}
```

Template remains:

```html
<section class="announcement-body" th:utext="${announcement.bodyHtml}"></section>
```

**Option 2: Use th:text if HTML rendering is not required**

In templates/announcement-preview.html, line 5:

```html
<section class="announcement-body" th:text="${announcement.bodyHtml}"></section>
```

This escapes the HTML and prevents XSS, but displays tags as literal text rather than rendering them.

## Explanation

The vulnerability exists because `th:utext` in Thymeleaf renders its content without HTML escaping, bypassing the protection that Thymeleaf's default `th:text` provides. When untrusted input is rendered through `th:utext`, attackers can inject malicious HTML and JavaScript that executes in victims' browsers.

Since the field is named `bodyHtml` and the test case contains a `<p>` tag, the intention is to render formatted HTML markup. According to the CWE-79 Java guidance, when a field carries markup, you must sanitize it using OWASP Java HTML Sanitizer (the `com.googlecode.owasp-java-html-sanitizer` library) with an explicit PolicyFactory that allowlists safe tags like `Sanitizers.FORMATTING` and `Sanitizers.BLOCKS`. The sanitized output can then be safely rendered through `th:utext`.

If HTML rendering is not actually needed, replace `th:utext` with `th:text` to escape the content and prevent XSS entirely.

## Behaviour changes

**Option 1 (sanitization)**: 
- Requires new dependency: `com.googlecode.owasp-java-html-sanitizer:owasp-java-html-sanitizer` (version to be confirmed against current releases and security advisories)
- Changes AnnouncementService to apply sanitization before returning bodyHtml
- Allows safe HTML markup to be rendered while stripping dangerous tags and attributes
- Preserves the visual rendering of formatted content

**Option 2 (th:text instead of th:utext)**:
- No new dependencies
- Template change only
- Strips all HTML markup and displays it as literal text
- Loses the visual formatting of the announcement body (tags appear as text to the user)
