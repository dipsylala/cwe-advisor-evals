## Verdict

Confirmed. `Export` is protected only by a bare `[Authorize]`, which verifies the caller is authenticated but performs no check that the caller is entitled to the specific `invoiceId` requested. Any authenticated user can supply an arbitrary invoice ID and receive that invoice's PDF, regardless of which account owns it. This is a missing-authorization (broken object-level authorization / IDOR) flaw, not a missing-authentication flaw.

## Source

`InvoiceExportController.Export(string invoiceId)` in `InvoiceExportController.cs`, line 19 (attribute on line 17). `invoiceId` is a user-controlled route parameter with no format or ownership constraint. It flows directly into `InvoiceRepository.LoadForExportAsync(invoiceId)`, which returns an `InvoiceExport` record carrying `PdfBytes`, `FileName`, and an `AccountId` that identifies the owning account. The controller never reads or compares that `AccountId` against the caller's identity before streaming `PdfBytes` back via `File(...)` on line 27 — the authorization check present (`[Authorize]`) confirms *who* is calling, but nothing confirms they are allowed to see *this* invoice.

## Fix

```csharp
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
            !string.Equals(callerAccountId, invoice.AccountId, System.StringComparison.Ordinal))
        {
            return Forbid();
        }

        return File(invoice.PdfBytes, "application/pdf", invoice.FileName);
    }
}
```

## Explanation

`[Authorize]` alone is authentication, not authorization: it rejects anonymous requests but treats every authenticated principal as equally entitled to every invoice. Because `invoiceId` is attacker-controlled and the repository already returns an `AccountId` that identifies the resource's rightful owner, the fix adds an explicit object-level ownership check between load and use — the standard remediation for CWE-862 in a resource-by-ID endpoint.

The added check reads the caller's account identifier from their authenticated claims (`User.FindFirst("account_id")`, matching the claim the application is expected to issue at sign-in) and compares it against `invoice.AccountId` using an ordinal string comparison, which avoids culture-sensitive comparison pitfalls for identifier values. A missing claim or a mismatch returns `403 Forbidden` via `Forbid()`, distinct from the `404 Not Found` already used for a genuinely absent invoice, so the two failure modes stay distinguishable in logs and client handling without leaking existence information beyond what the current behavior already reveals.

This keeps the change local to the action method: it does not alter the repository contract, the route shape, or the authentication attribute, and it generalizes past this one endpoint to the same pattern anywhere an ID from the route or body is used to fetch a record that carries an owner — the fix is always to compare that owner against the authenticated caller before returning the resource, never to rely on `[Authorize]` alone to imply ownership.
