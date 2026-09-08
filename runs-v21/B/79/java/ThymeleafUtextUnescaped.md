## Verdict

exploitable

## Source

Line 24: `@RequestParam("note") String submitterNote` — user-controlled HTTP request parameter receives untrusted input.

## Fix

### File: ThymeleafUtextUnescaped.java

```java
package evalcases;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.StringTemplateResolver;

@RestController
class SupportTicketPreviewController {

    private final TemplateEngine templateEngine;

    public SupportTicketPreviewController() {
        StringTemplateResolver resolver = new StringTemplateResolver();
        resolver.setTemplateMode(TemplateMode.HTML);
        this.templateEngine = new TemplateEngine();
        this.templateEngine.setTemplateResolver(resolver);
    }

    @PostMapping("/tickets/preview")
    public String previewTicketNote(@RequestParam("note") String submitterNote) {
        // Renders a live preview of the submitted note using an inline Thymeleaf fragment
        String fragment = "<div class=\"ticket-note\" th:text=\"${note}\">Preview</div>";

        Context context = new Context();
        context.setVariable("note", submitterNote);

        // SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
        return templateEngine.process(fragment, context);
    }
}
```

## Explanation

The vulnerability occurs because the template fragment at line 26 uses `th:utext` (Thymeleaf's unescaped text directive), which outputs the `note` variable without any HTML entity encoding. An attacker can supply a note parameter containing JavaScript payloads such as `<img src=x onerror=alert(1)>` or `<script>...</script>`, which are rendered as-is into the HTML response and executed in the victim's browser.

The fix changes `th:utext` to `th:text` on line 26. Thymeleaf's `th:text` directive automatically applies HTML entity encoding to the output, converting dangerous characters (`<`, `>`, `&`, `"`, `'`) into their safe HTML entity equivalents. This ensures that user-supplied input is treated as text content rather than executable code, preventing XSS attacks while preserving the intended rendering behavior.

## Behaviour changes

none

The fix preserves the sink contract: `th:text` still renders the note value into the HTML response at the same location and produces the same visual output for legitimate content. The only difference is that dangerous characters are now encoded, which is the correct and secure behavior. No additional parameters, arguments, or return values were added; only the escaping mechanism was corrected.
