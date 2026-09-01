package cases.mybatis;

import java.util.List;

public class InvoiceService {
    private final InvoiceMapper mapper;

    public InvoiceService(InvoiceMapper mapper) {
        this.mapper = mapper;
    }

    public List<InvoiceRow> listInvoices(String tenantId, String sort) {
        return mapper.findForTenant(tenantId, sort);
    }
}
