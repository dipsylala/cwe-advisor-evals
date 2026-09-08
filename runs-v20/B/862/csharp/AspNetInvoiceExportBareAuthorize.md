## Verdict

Confirmed. `InvoiceExportController.Export` carries a bare `[Authorize]`, which only proves the caller is authenticated. It never checks that the caller is entitled to the specific invoice it loads, so any authenticated user can supply any `invoiceId` and download another account's PDF (CWE-862, missing resource-level authorization / IDOR).

## Source

`invoiceId` - the route parameter on `GET /api/invoices/{invoiceId}/export` - is attacker-controlled: any authenticated caller can put any value there.

## Fix

### File: InvoiceExportController.cs

```csharp
using System.Security.Claims;
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

        var callerAccountId = User.FindFirstValue("account_id");
        if (string.IsNullOrEmpty(callerAccountId) || !string.Equals(callerAccountId, invoice.AccountId, StringComparison.Ordinal))
        {
            // Answer identically to "not found" so a guessable invoiceId cannot be used
            // to enumerate which IDs exist versus which ones belong to another account.
            return NotFound();
        }

        return File(invoice.PdfBytes, "application/pdf", invoice.FileName);
    }
}
```

## Explanation

`[Authorize]` alone confirms the caller is logged in but performs no check against the specific record being fetched - it is the exact "bare `[Authorize]`" gap the C# CWE-862 guidance calls out. The repository's `InvoiceExport` record already carries an `AccountId`, which is the ownership fact the sink needs but the original code never reads. The fix loads the invoice (unchanged), then compares the caller's account claim against `invoice.AccountId` before the file bytes are returned, closing the object-level gap while leaving the `[Authorize]` authentication gate, the DI-injected `_invoices` dependency, the `NotFound()` behavior for a non-existent invoice, and the successful `File(...)` response shape all untouched.

Per the general CWE-862 guidance, a guessable-identifier ownership failure should read identically to "does not exist" rather than confirming the record's existence with a 403 - both branches here return `NotFound()`, matching the existing not-found path and avoiding a new enumeration oracle. `InvoiceRepository.LoadForExportAsync` cannot be changed to scope the query itself (`WHERE id = ? AND owner_id = ?`), since it is part of the shared fixture, so the check is applied on the loaded resource instead, which is the fallback the same guidance describes ("Check ownership against a server-loaded copy of the resource").

Assumption: the fix reads the caller's account identifier from a claim named `account_id` on `User` (`ClaimsPrincipal`). No login/claims-issuance code is present in the two-file call chain, so the exact claim type the application issues at sign-in could not be confirmed from the provided files; `account_id` is a placeholder for whatever claim the app's authentication scheme already sets to the authenticated user's account/tenant identifier, and should be swapped for the real claim type when wiring this in. The language guidance's alternative pattern - a resource-based `IAuthorizationHandler` invoked through `IAuthorizationService.AuthorizeAsync` - was not used here: that mechanism requires the handler to be registered in the application's service collection (`Program.cs`), which is outside this case's two-file call chain, and without that registration `AuthorizeAsync` would fail closed for every caller, including legitimate owners, turning the fix into a regression rather than a scoped one. The inline comparison above is self-contained and does not depend on wiring not shown here.

Verified: the fixed controller was compiled (`dotnet build`, .NET 10 SDK) against an unmodified copy of the provided `InvoiceRepository.cs` in a scratch ASP.NET Core project; build succeeded with no errors. Every symbol the fix adds - `ClaimsPrincipal`/`User.FindFirstValue` (from `System.Security.Claims`, already implicitly available via `ControllerBase.User`), `string.Equals`/`string.IsNullOrEmpty` (`System`) - is standard-library and unchanged from the original file's dependencies otherwise.

## Behaviour changes

- A caller who is authenticated but whose `account_id` claim does not match the invoice's owning account now receives `404 Not Found` instead of the invoice PDF. This is the intended fix, not a side effect.
- The `account_id` claim name is an assumption (see Explanation) - it must be aligned with whatever claim the application's real authentication setup issues for the caller's account/tenant identity before this is merged.
- No other endpoint, status code, or return path was altered.
