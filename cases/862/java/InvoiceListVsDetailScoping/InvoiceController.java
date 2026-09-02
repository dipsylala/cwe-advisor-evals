package cases.authorization;

import java.util.List;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class InvoiceController {
    private final InvoiceRepository repository;

    public InvoiceController(InvoiceRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/api/invoices/{id}")
    public Invoice getInvoice(@PathVariable Long id, Authentication authentication) {
        return repository.findByIdAndOwnerUsername(id, authentication.getName())
                .orElseThrow();
    }

    @GetMapping("/api/invoices")
    public List<Invoice> listInvoices() {
        // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
        return repository.findAll();
    }
}
