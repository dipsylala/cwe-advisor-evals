## Verdict
Confirmed. The vulnerability is a direct XSS sink caused by using Thymeleaf's unescaped text directive `th:utext` with user-controlled input.

## Source
User input flows from the `@RequestParam("note")` annotation on line 24 into the `submitterNote` variable, which is then placed into the template fragment on line 26 and rendered on line 32 without any escaping via `th:utext`.

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
The vulnerability stems from using `th:utext` (unescaped text) on line 26, which renders the variable without HTML escaping. When user-supplied input like `<script>alert('xss')</script>` is passed via the `note` parameter, it executes in the browser context of any user viewing the preview.

The fix replaces `th:utext` with `th:text`, which is the standard Thymeleaf directive for escaping output. `th:text` automatically converts dangerous characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents, preventing script injection. This preserves the intended functionality—displaying the user's note in the preview—while neutralizing the XSS attack vector.
