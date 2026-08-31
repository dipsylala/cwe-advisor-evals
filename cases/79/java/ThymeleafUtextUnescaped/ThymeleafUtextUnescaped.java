package evalcases;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.StringTemplateResolver;

@RestController
public class SupportTicketPreviewController {

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
        String fragment = "<div class=\"ticket-note\" th:utext=\"${note}\">Preview</div>";

        Context context = new Context();
        context.setVariable("note", submitterNote);

        // SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
        return templateEngine.process(fragment, context);
    }
}
