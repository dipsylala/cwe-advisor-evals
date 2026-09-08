## Verdict

Confirmed. `Export` is decorated with a bare `[Authorize]`, which only proves the caller is authenticated - it does not check that the authenticated caller is entitled to the specific invoice being requested. `InvoiceRepository.LoadForExportAsync` looks the record up by `invoiceId` alone and returns it regardless of which account owns it (`InvoiceExport.AccountId`), so any logged-in user who can guess or enumerate an `invoiceId` can download another account's invoice PDF. This is a missing object-level authorization check (CWE-862).

## Source

`invoiceId` is an attacker-controlled route parameter on `GET api/invoices/{invoiceId}/export` (`InvoiceExportController.cs`, line 17/19). It flows unchecked into `_invoices.LoadForExportAsync(invoiceId)`, and the resulting `InvoiceExport` (which carries the owning `AccountId`) is returned to the caller via `File(...)` with no comparison against the caller's own identity.

## Fix

### File: InvoiceExportController.cs

```csharp
using System;
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

        var callerAccountId = User.FindFirst("account_id")?.Value;
        if (string.IsNullOrEmpty(callerAccountId) ||
            !string.Equals(callerAccountId, invoice.AccountId, StringComparison.Ordinal))
        {
            return Forbid();
        }

        return File(invoice.PdfBytes, "application/pdf", invoice.FileName);
    }
}
```

## Explanation

`[Authorize]` alone only enforces authentication - it establishes that a valid principal is present, not that the principal owns the resource named in the route. The fix keeps the existing lookup and existence check unchanged, then adds an explicit ownership comparison: it reads the caller's own account id from their claims (`account_id`, the tenant/account claim issued at sign-in) and compares it against `invoice.AccountId`, the owning account already returned by the repository. A missing claim or a mismatch results in `403 Forbidden` via `Forbid()`, distinct from the `404 Not Found` already used for a genuinely nonexistent invoice, so an authenticated-but-unauthorized request is rejected before the PDF bytes are ever streamed back. No repository or data-access change is required - the fix closes the gap purely by checking data the repository already returns.
