## Verdict

The endpoint is vulnerable to CSRF because it performs a state-changing operation (email update) without validating the antiforgery token. Although `app.UseAntiforgery()` is registered, minimal API endpoints do not automatically validate tokens — explicit validation is required.

## Source

Line 27 calls `UpdateEmailAsync()` without first validating the request's antiforgery token. The `IAntiforgery` service is available but not invoked.

## Fix

Add `ValidateRequestAsync()` before the state-changing operation:

```csharp
app.MapPost("/account/email", async (EmailChangeRequest request, AccountService accounts, HttpContext context, IAntiforgery antiforgery) =>
{
    var userId = context.User.FindFirst("sub")?.Value;
    if (userId is null)
    {
        return Results.Unauthorized();
    }

    await antiforgery.ValidateRequestAsync(context);
    await accounts.UpdateEmailAsync(userId, request.NewEmail);
    return Results.Accepted();
}).RequireAuthorization();
```

The fix adds `IAntiforgery` as a dependency (automatically injected by the minimal API framework) and calls `ValidateRequestAsync(context)` before the state change. This verifies the request carries a valid antiforgery token matching the session.

## Explanation

CSRF vulnerabilities in minimal APIs require explicit token validation because the `[ValidateAntiForgeryToken]` attribute does not apply. The vulnerability exists because the request handler receives a JSON-bound model and immediately acts on it without checking whether the request originated from a legitimate, same-origin form. Adding `IAntiforgery.ValidateRequestAsync()` verifies the session-bound token is present and valid, preventing a cross-origin attacker from forging the request.
