## Verdict

The vulnerability is confirmed and remediated. The code passes untrusted user input directly to Thymeleaf's `th:utext` attribute, which is an explicit auto-escaping bypass that allows XSS injection. Replacing `th:utext` with `th:text` enables Thymeleaf's default HTML entity encoding for the output context.

## Source

`submitterNote` parameter on line 24 - untrusted user input from HTTP request.

## Fix

Change line 26 from `th:utext` to `th:text` to enable automatic HTML entity escaping:

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

        return templateEngine.process(fragment, context);
    }
}
```

## Explanation

Thymeleaf's `th:text` attribute applies automatic HTML entity encoding to context variables, converting characters like `<`, `>`, `&`, and quotes to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`). This prevents injected script tags, event handlers, and other HTML markup from being interpreted as code. The attacker-controlled `note` variable is now treated as text content, not markup, eliminating the XSS injection point. The change preserves the original functionality - legitimate note text containing special characters renders correctly with those characters escaped and visible.

## Behaviour changes

Users can no longer inject executable HTML or JavaScript into ticket note previews. Text containing special characters (e.g., `<`, `>`, `&`) now displays those characters literally rather than being interpreted as markup. For example, a note containing `<img src=x onerror=alert(1)>` now displays as literal text instead of executing a script. Legitimate content is unaffected - regular text, numbers, and punctuation render normally.
