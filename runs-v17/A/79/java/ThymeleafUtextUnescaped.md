## Verdict

The vulnerability is confirmed. The code uses Thymeleaf's `th:utext` attribute to render user-supplied input without escaping, enabling XSS injection attacks.

## Source

Line 26 constructs a Thymeleaf template fragment with `th:utext="${note}"`, and line 32 processes this fragment with unsanitized user input from the `submitterNote` parameter.

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

Changed `th:utext` to `th:text` on line 26. The `th:text` attribute automatically HTML-escapes the variable value before rendering, converting characters like `<`, `>`, `&`, `"`, and `'` to their entity equivalents. This prevents any HTML or JavaScript injected through the `note` parameter from being executed in the browser. The `th:utext` attribute was rendering the content unescaped, allowing attackers to inject arbitrary scripts through malicious input.
