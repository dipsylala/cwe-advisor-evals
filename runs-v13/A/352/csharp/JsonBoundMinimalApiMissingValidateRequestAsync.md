## Verdict

Confirmed. The POST endpoint at line 18-29 performs a state-changing operation (email update) without validating an antiforgery token, leaving it vulnerable to cross-site request forgery attacks.

## Source

Line 27 in Program.cs:
```csharp
await accounts.UpdateEmailAsync(userId, request.NewEmail);
```

The endpoint is defined at line 18 as a `MapPost` handler that accepts `EmailChangeRequest` from JSON body binding. Although the application registers antiforgery services (line 9) and middleware (line 16), the handler does not validate the antiforgery token before executing the state-changing operation.

## Fix

Inject `IAntiforgery` into the endpoint handler and call `ValidateRequestAsync()` before the state-changing operation:

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

## Explanation

Cross-Site Request Forgery (CWE-352) exploits the browser's automatic inclusion of cookies in cross-origin requests. When a user is authenticated via cookies and visits a malicious site, JavaScript on that site can forge a request to this POST endpoint, causing the user's email to be changed without their knowledge.

ASP.NET Core's antiforgery system mitigates this by requiring a unique token that only the legitimate application can generate and validate. The token must be:
1. Included in the HTML form (or request header) by the legitimate client
2. Validated by the server before processing the request

The fix adds the validation call at line 10 of the patched handler. This call verifies that the current request carries a valid antiforgery token matching the current user's session. If validation fails (missing token, invalid token, or token mismatch), `ValidateRequestAsync()` throws an exception that returns HTTP 400, preventing the state change.

JSON-bound minimal APIs do not automatically validate antiforgery tokens—the developer must explicitly call `IAntiforgery.ValidateRequestAsync()` as shown above.
