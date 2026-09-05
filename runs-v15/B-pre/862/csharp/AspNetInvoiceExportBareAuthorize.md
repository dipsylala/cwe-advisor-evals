## Verdict

**Confirmed.** The `Export` action verifies authentication with `[Authorize]` but performs no resource-level authorization check. An authenticated user can export any invoice by changing the `invoiceId` parameter, regardless of ownership.

## Source

**File:** `InvoiceExportController.cs`  
**Line:** 17

```csharp
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
```

The vulnerability: `[Authorize]` confirms the caller is authenticated but does not verify they own the invoice being exported. The repository method `LoadForExportAsync` also performs no ownership scoping—it loads any invoice by ID.

## Fix

**Modified `InvoiceExportController.cs`:**

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Cases.Authorization;

[ApiController]
[Route("api/invoices")]
public sealed class InvoiceExportController : ControllerBase
{
    private readonly InvoiceRepository _invoices;
    private readonly IAuthorizationService _authorizationService;

    public InvoiceExportController(InvoiceRepository invoices, IAuthorizationService authorizationService)
    {
        _invoices = invoices;
        _authorizationService = authorizationService;
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

        var authResult = await _authorizationService.AuthorizeAsync(User, invoice, "CanExportInvoice");
        if (!authResult.Succeeded)
        {
            return Forbid();
        }

        return File(invoice.PdfBytes, "application/pdf", invoice.FileName);
    }
}
```

**Register the authorization handler in `Program.cs`:**

Add an authorization handler to verify invoice ownership:

```csharp
services.AddAuthorization(options =>
{
    options.AddPolicy("CanExportInvoice", policy =>
        policy.Requirements.Add(new InvoiceOwnershipRequirement()));
});

services.AddSingleton<IAuthorizationHandler, InvoiceOwnershipHandler>();
```

**Create an authorization handler** (e.g., in a new file `InvoiceOwnershipHandler.cs`):

```csharp
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace Cases.Authorization;

public sealed class InvoiceOwnershipRequirement : IAuthorizationRequirement
{
}

public sealed class InvoiceOwnershipHandler : AuthorizationHandler<InvoiceOwnershipRequirement, InvoiceExport>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        InvoiceOwnershipRequirement requirement,
        InvoiceExport resource)
    {
        var userAccountId = context.User.FindFirst("acct_id")?.Value;
        
        if (!string.IsNullOrEmpty(userAccountId) && userAccountId == resource.AccountId)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
```

(Assumes the authenticated principal carries an `acct_id` claim. Adapt the claim name to match your authentication provider's claim naming convention.)

## Explanation

The fix adds a resource-level authorization check that verifies the authenticated user owns the invoice before returning it. The check happens server-side through `IAuthorizationService.AuthorizeAsync`, which delegates to an `IAuthorizationHandler` that compares the invoice's `AccountId` against the authenticated user's account claim.

**Why this approach:**
- **Authentication vs. Authorization:** `[Authorize]` confirms "is the user logged in?"; the new check confirms "does this user own this resource?"
- **Centralized enforcement:** The handler encapsulates ownership logic in one place, making it reusable across endpoints that operate on invoices.
- **Fails closed:** If the user's account claim is missing or does not match the invoice's `AccountId`, the handler does not call `context.Succeed()`, and the endpoint returns `Forbid()` instead of proceeding.
- **Proper response code:** A 403 (Forbid) correctly indicates the resource exists but the authenticated user is not permitted to access it; a 404 (NotFound) would inappropriately hide the invoice's existence.

## Behaviour changes

**Before:**
- An authenticated user (any authenticated user) can request `/api/invoices/{any-id}/export` and download any invoice, regardless of ownership.

**After:**
- An authenticated user can only request `/api/invoices/{id}/export` if the invoice with that ID belongs to their account (matching their `acct_id` claim).
- If the user lacks the required claim or their account ID does not match the invoice's `AccountId`, the endpoint returns 403 Forbidden.
- Unauthenticated requests receive a 401 Challenge (handled by the authentication middleware in response to `[Authorize]`).
