package cases.mybatis;

import java.util.List;

public class InvoiceController {
    private final InvoiceService service;

    public InvoiceController(InvoiceService service) {
        this.service = service;
    }

    public List<InvoiceRow> listInvoices(String tenantId, String sort) {
        return service.listInvoices(tenantId, sort == null ? "created_at" : sort);
    }
}
