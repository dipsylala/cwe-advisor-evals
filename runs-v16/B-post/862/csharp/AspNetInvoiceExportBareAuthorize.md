## Verdict

Exploitable

## Source

User-supplied `invoiceId` parameter from URL route `{invoiceId}/export`, line 19.

## Fix

**Vulnerable Code:**

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

The `[Authorize]` attribute on line 17 only verifies authentication; it does not verify that the authenticated user has permission to access this invoice.

**Fixed Code:**

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

        // Verify the current user owns this invoice
        var userAccountId = User.FindFirst("account_id")?.Value;
        if (string.IsNullOrEmpty(userAccountId) || userAccountId != invoice.AccountId)
        {
            return Forbid();
        }

        return File(invoice.PdfBytes, "application/pdf", invoice.FileName);
    }
```

## Explanation

The fix adds a resource-based authorization check after loading the invoice. It compares the authenticated user's `account_id` claim against the invoice's `AccountId` field loaded from the database. If the user's account does not match the invoice's owner, the action returns `Forbid()`, denying access. This ensures that an authenticated user cannot bypass the authorization by simply changing the `invoiceId` parameter in the URL to access invoices belonging to other accounts. The check runs server-side against a server-loaded copy of the resource, not a client-supplied value.

## Behaviour changes

**Added authorization check**: The method now verifies resource ownership before returning the invoice. An authenticated user without the matching `account_id` claim will receive a 403 Forbid response instead of the PDF file.

**Claim dependency**: The fix assumes the authenticated user carries an `account_id` claim in their identity. If this claim is not present, all invoice exports will be denied. This is the correct fail-closed behavior per CWE-862 guidance: "if the authorization decision cannot be evaluated, deny the request rather than default to allow."
