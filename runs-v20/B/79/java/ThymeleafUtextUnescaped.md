## Verdict

Confirmed. CWE-79 (Cross-Site Scripting) - the inline Thymeleaf fragment binds attacker-controlled input to `th:utext`, which writes the value into the response without HTML-escaping.

## Source

`@RequestParam("note") String submitterNote` in `SupportTicketPreviewController.previewTicketNote` - a request parameter supplied directly by the client, with no validation or encoding applied before use.

## Fix

`submitterNote` is assigned to the Thymeleaf context variable `note` (`context.setVariable("note", submitterNote)`), which the inline fragment `<div class="ticket-note" th:utext="${note}">Preview</div>" ` renders with `th:utext`. Thymeleaf's `th:utext` explicitly disables output escaping, so any HTML/JS in `submitterNote` (e.g. `<script>...</script>` or `<img src=x onerror=...>`) is written verbatim into the string returned by `templateEngine.process(...)`, which is itself the full HTTP response body (the controller is a `@RestController` returning `String`).

`note` is a free-text support-ticket note - a plain-text field, not a field the application intends to carry markup - so the correct fix is to stop treating it as pre-sanitized HTML rather than to sanitize it as markup. Replacing `th:utext` with `th:text` on the same expression makes Thymeleaf HTML-escape the value while rendering it in the identical position, closing the injection with no sanitizer dependency needed.

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

`th:utext` is Thymeleaf's unescaped-text attribute - a documented auto-escaping bypass - and the CWE-79 Java guidance treats it as a taint sink whenever the bound expression carries untrusted data. `submitterNote` is attacker-controlled request input with no upstream validation or encoding, so it reaches that sink unmodified. Switching the attribute to `th:text` keeps the exact same data flow and rendering position but routes the value through Thymeleaf's default HTML entity escaping, so `<`, `>`, `&`, `"` and `'` in the note are rendered as literal text instead of being parsed as markup or script. No sanitizer library is warranted here because the field is a plain-text ticket note, not a field the application intends to hold markup (a rich-text or HTML body field would instead call for the OWASP Java HTML Sanitizer with an explicit `PolicyFactory`, keeping `th:utext` for the sanitized output). This is the only change: the fragment string literal is otherwise unchanged, `context.setVariable` still binds the same variable name, and the method's signature, return type, and `templateEngine.process(...)` call are untouched.

## Behaviour changes

The preview response no longer renders any HTML/markup a submitter includes in their note - angle brackets, ampersands, and quotes now appear as literal escaped text (e.g. `&lt;b&gt;` instead of a live `<b>` tag) rather than being interpreted as markup. Any legitimate use case that relied on the preview rendering rich-text formatting from the note field will need a dedicated markup-sanitization path instead; this fix assumes no such use case exists based on the field being a plain support-ticket note.

Compiler check: `javac` was run against the fixed file in isolation (no project classpath available in this environment). All reported errors are unresolved Spring/Thymeleaf package/symbol references from the missing classpath, identical in kind and location to what the same command produces against the original unmodified file; no syntax errors were introduced, and the only functional change (`th:utext` to `th:text`) is a string-literal content change, not a Java-syntax construct javac can validate further.
