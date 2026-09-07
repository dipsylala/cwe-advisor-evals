## Verdict

VULNERABLE. The `th:utext` directive at line 26 renders user-controlled input without HTML escaping, allowing reflected XSS injection via the `note` parameter.

## Source

The vulnerability originates from the `submitterNote` parameter at line 24, which receives untrusted user input via `@RequestParam("note")`.

The parameter flows into the Thymeleaf context at line 29 as the variable `note`, then into the template fragment string at line 26 using the `th:utext` directive, which explicitly disables HTML escaping. The rendered output is returned directly to the browser at line 32 via `templateEngine.process()`.

An attacker can inject a payload such as `<img src=x onerror="alert('xss')">` or `<script>alert('xss')</script>` via the note parameter, which will execute in the victim's browser when the response is rendered.

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

        // FIXED: Changed th:utext to th:text to enable HTML escaping of user input
        return templateEngine.process(fragment, context);
    }
}
```

## Explanation

The fix replaces `th:utext` with `th:text` at line 26. The `th:utext` directive explicitly bypasses Thymeleaf's default HTML escaping and renders content verbatim, whereas `th:text` applies automatic HTML entity encoding to the variable value. This encoding converts dangerous characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`), preventing the browser from interpreting injected markup or script tags as executable code.

The Thymeleaf documentation and Java CWE-79 guidance both confirm that `th:text` is the safe default for rendering user-controlled content. The fix preserves the existing contract: it still returns a rendered HTML string to the response, and legitimate content containing special characters (e.g., product notes with `&`, `<`, or quotes) will render correctly as escaped text rather than as HTML syntax.

## Behaviour changes

- User input containing HTML metacharacters will now appear as literal text with encoded entities (e.g., `<script>` displays as `&lt;script&gt;`) instead of being interpreted as markup.
- Legitimate content is unaffected: text, numbers, spaces, and punctuation render identically; only HTML-special characters are escaped.
- XSS payloads are neutralized: injected event handlers, script tags, and attribute breakouts will not execute because they are rendered as literal text.
- This is the intended, safe default behavior for user-generated content in web templates.
