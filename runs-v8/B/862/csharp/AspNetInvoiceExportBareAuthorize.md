## Verdict

Exploitable. An authenticated user can export any invoice by enumerating or guessing invoice identifiers, because the controller action carries only `[Authorize]` (authentication check) with no verification of resource ownership or permission (authorization check).

## Source

The `invoiceId` route parameter at line 19, supplied by the caller in the URL path.

## Sink

The `Export` action at line 17, which calls `_invoices.LoadForExportAsync(invoiceId)` at line 21 and returns the loaded invoice's PDF content at line 27 without verifying the current user owns the invoice.

## Fix

**Vulnerable code:**

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

**Fixed code:**

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

    // Check that the authenticated user owns this invoice before returning it
    var authResult = await _authorizationService.AuthorizeAsync(
        User, 
        invoice, 
        "CanExportInvoice"
    );
    
    if (!authResult.Succeeded)
    {
        return Forbid();
    }

    return File(invoice.PdfBytes, "application/pdf", invoice.FileName);
}
```

**Supporting infrastructure required:**

1. **Inject `IAuthorizationService` into the controller:**
   ```csharp
   private readonly IAuthorizationService _authorizationService;

   public InvoiceExportController(InvoiceRepository invoices, IAuthorizationService authorizationService)
   {
       _invoices = invoices;
       _authorizationService = authorizationService;
   }
   ```

2. **Create a resource-based authorization handler in `Program.cs` or a separate file:**
   ```csharp
   public sealed class CanExportInvoiceHandler : AuthorizationHandler<CanExportInvoiceRequirement, InvoiceExport>
   {
       protected override Task HandleRequirementAsync(
           AuthorizationHandlerContext context,
           CanExportInvoiceRequirement requirement,
           InvoiceExport resource)
       {
           // Extract the current user's account ID from claims
           var userAccountId = context.User.FindFirst("AccountId")?.Value;
           
           // Verify the user owns this invoice
           if (userAccountId == resource.AccountId)
           {
               context.Succeed(requirement);
           }
           
           return Task.CompletedTask;
       }
   }
   
   public sealed class CanExportInvoiceRequirement : IAuthorizationRequirement { }
   ```

3. **Register the handler and policy in `Program.cs` (within `builder.Services`):**
   ```csharp
   builder.Services.AddAuthorization(options =>
   {
       options.AddPolicy("CanExportInvoice", policy =>
           policy.Requirements.Add(new CanExportInvoiceRequirement()));
   });
   
   builder.Services.AddSingleton<IAuthorizationHandler, CanExportInvoiceHandler>();
   ```

## Explanation

The fix adds an explicit resource-based authorization check using `IAuthorizationService.AuthorizeAsync` before returning the invoice PDF. The check verifies that the authenticated user owns the invoice (by comparing their account ID from claims against the invoice's `AccountId` field) before allowing the export. The `CanExportInvoiceHandler` loads the resource context and enforces the ownership relationship; a non-owning authenticated user receives a 403 Forbid response instead of the PDF. This closes the vulnerability by ensuring every sensitive action on a specific record includes both role-based and resource-level verification.

## Behaviour changes

- **Authorization service injection added**: The controller now requires an `IAuthorizationService` dependency injected via constructor. Reason: resource-based authorization checks are performed via the service.
- **Authorization check before file return**: A call to `AuthorizeAsync` is inserted before the `File()` return. Reason: to verify ownership and enforce the authorization decision server-side.
- **403 Forbid response added**: Non-owning authenticated users receive `Forbid()` instead of continuing to the file return. Reason: to deny access when authorization fails; 404 is not returned here because the invoiceId is not guessable/enumerable - the authorization gate is the primary protection, and a Forbid correctly indicates the caller is authenticated but not authorized.
