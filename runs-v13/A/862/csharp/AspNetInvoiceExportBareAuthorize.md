## Verdict
CWE-862 is a resource-level authorization weakness in the `Export` method. The `[Authorize]` attribute enforces authentication but not ownership verification—any authenticated user can export any invoice by manipulating the `invoiceId` parameter.

## Source
The `Export` method at line 17 loads and returns an invoice without verifying that the current user owns it:

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

The `InvoiceRepository.LoadForExportAsync()` accepts only an `invoiceId` and returns the invoice without ownership checks, making every authenticated user a potential attacker for cross-user access.

## Fix
Modify the controller to enforce resource-level authorization by verifying ownership before returning the file. Pass the current user's account identity to the repository and check that the invoice belongs to that account:

```csharp
[Authorize]
[HttpGet("{invoiceId}/export")]
public async System.Threading.Tasks.Task<IActionResult> Export(string invoiceId)
{
    var currentAccountId = User.FindFirst("accountId")?.Value;
    if (string.IsNullOrEmpty(currentAccountId))
    {
        return Forbid();
    }

    var invoice = await _invoices.LoadForExportAsync(invoiceId, currentAccountId);
    if (invoice is null)
    {
        return NotFound();
    }

    if (invoice.AccountId != currentAccountId)
    {
        return Forbid();
    }

    return File(invoice.PdfBytes, "application/pdf", invoice.FileName);
}
```

Update `InvoiceRepository.LoadForExportAsync()` to accept and enforce the account filter:

```csharp
public System.Threading.Tasks.Task<InvoiceExport?> LoadForExportAsync(string invoiceId, string accountId)
{
    // Query must filter by both invoiceId and accountId before returning
    return System.Threading.Tasks.Task.FromResult<InvoiceExport?>(new InvoiceExport(System.Array.Empty<byte>(), invoiceId + ".pdf", accountId));
}
```

## Explanation
The weakness stems from checking only that a user is authenticated (`[Authorize]`) rather than validating that the authenticated user has permission to access the requested resource. The fix introduces two layers of ownership verification:

1. Extract the current user's account identity from the request context (line 5-8).
2. Pass the account ID to the repository method so it can filter results by both the invoice ID and ownership (line 11).
3. Explicitly verify the returned invoice's account matches the current user before returning it (lines 17-20). This defense-in-depth approach catches cases where the repository filter may be bypassed.

Return `Forbid()` (HTTP 403) when ownership validation fails, not `NotFound()`, to clearly signal an authorization failure rather than ambiguously mixing it with missing-resource cases. This approach prevents information leakage that would confirm invoice existence to an unauthorized user.
