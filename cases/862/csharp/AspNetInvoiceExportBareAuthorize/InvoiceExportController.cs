using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Cases.Authorization;

[ApiController]
[Route("api/invoices")]
public sealed class InvoiceExportController : ControllerBase
{
    private readonly InvoiceRepository _invoices;

    public InvoiceExportController(InvoiceRepository invoices)
    {
        _invoices = invoices;
    }

    [Authorize]
    [HttpGet("{invoiceId}/export")]
    public async System.Threading.Tasks.Task<IActionResult> Export(string invoiceId)
    {
        var invoice = await _invoices.LoadForExportAsync(invoiceId);
        if (invoice is null)
        {
            return NotFound();
        }

        return File(invoice.PdfBytes, "application/pdf", invoice.FileName);
    }
}
