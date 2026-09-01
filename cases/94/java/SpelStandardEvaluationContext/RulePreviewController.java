package cases.codeinjection;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RulePreviewController {
    private final RulePreviewService service;

    public RulePreviewController(RulePreviewService service) {
        this.service = service;
    }

    @PostMapping("/rules/preview")
    public Object preview(@RequestBody RulePreviewRequest request) {
        return service.preview(request.expression(), new OrderContext(42, 3));
    }
}

record RulePreviewRequest(String expression) {}
record OrderContext(int total, int tax) {}
