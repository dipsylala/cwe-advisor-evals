package cases.mybatis;

import java.util.List;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

public interface InvoiceMapper {
    @Select("SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY ${sort}")
    List<InvoiceRow> findForTenant(@Param("tenantId") String tenantId, @Param("sort") String sort);
}

record InvoiceRow(String id, String status, long totalCents) {}
