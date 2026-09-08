## Verdict

Confirmed. `previewTicketNote` renders the attacker-controlled `note` request parameter into an HTML response using Thymeleaf's `th:utext` attribute, which outputs its expression result without HTML-escaping. A submitted note such as `<script>...</script>` or an `<img onerror=...>` payload is emitted verbatim into the response body and executes in the browser of anyone who views the rendered preview.

## Source

`submitterNote`, the `note` request parameter bound via `@RequestParam("note") String submitterNote` in `SupportTicketPreviewController.previewTicketNote`, is attacker-controlled input.

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

        return templateEngine.process(fragment, context);
    }
}
```

## Explanation

Thymeleaf provides two attributes for inserting an expression's result as an element's body: `th:utext` ("unescaped text"), which writes the raw string into the HTML output, and `th:text`, which HTML-escapes the result before writing it (`<`, `>`, `&`, `"`, `'` become their entity equivalents). The only change needed is swapping `th:utext="${note}"` for `th:text="${note}"` on the fragment's `div`; `th:text` is the framework's own standard mechanism for outputting untrusted or dynamic content into an HTML template mode, so no additional library or manual encoding call is required.

This closes the injection because the note is only ever rendered as the text content of a `div` - there is no legitimate requirement in this feature (a plain-text ticket note preview) for the submitter to author HTML or script that executes in another user's browser. `th:utext` should be reserved for values the application itself constructs and trusts (e.g. server-generated markup fragments), never for a value that originates from a request parameter.

After the change, verify by submitting a note containing `<script>alert(1)</script>`: the rendered response should contain the escaped sequence `&lt;script&gt;alert(1)&lt;/script&gt;` inside the `div`, and the browser should display the text literally rather than executing it - confirming the payload is neutralized rather than merely reformatted.
