## Verdict

The endpoint at line 27 modifies user state (updates email) without validating anti-forgery tokens. Although `app.UseAntiforgery()` middleware is registered, it does not enforce validation for JSON-bound minimal API endpoints — only form-bound ones. An attacker can craft a cross-origin POST request with JSON body to change a victim's email if the victim visits the attacker's site while authenticated.

**Status:** VULNERABLE

## Source

File: `Program.cs` (case relative path)
Line: 27
Endpoint: `POST /account/email`
Vulnerability: Missing CSRF token validation on JSON-bound minimal API endpoint

The code accepts JSON via `EmailChangeRequest request` parameter binding. The middleware `app.UseAntiforgery()` at line 16 runs, but according to ASP.NET Core documentation, automatic token validation in the middleware applies only to form-bound endpoints (`IFormCollection`, `IFormFile`, `[FromForm]`). JSON-bound endpoints must explicitly call `await antiforgery.ValidateRequestAsync(context)` to enforce the check.

## Fix

### File: Program.cs

```csharp
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie();
builder.Services.AddAuthorization();
builder.Services.AddAntiforgery();
builder.Services.AddScoped<AccountService>();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapPost("/account/email", async (EmailChangeRequest request, AccountService accounts, HttpContext context, IAntiforgery antiforgery) =>
{
    var userId = context.User.FindFirst("sub")?.Value;
    if (userId is null)
    {
        return Results.Unauthorized();
    }

    await antiforgery.ValidateRequestAsync(context);

    // SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
    await accounts.UpdateEmailAsync(userId, request.NewEmail);
    return Results.Accepted();
}).RequireAuthorization();

app.Run();

public record EmailChangeRequest(string NewEmail);

public class AccountService
{
    public Task UpdateEmailAsync(string userId, string newEmail)
    {
        Console.WriteLine($"Updating email for {userId} to {newEmail}");
        return Task.CompletedTask;
    }
}
```

## Explanation

The fix injects the `IAntiforgery` service into the route handler and calls `await antiforgery.ValidateRequestAsync(context)` before processing the email update request. This enforces CSRF token validation for JSON-bound endpoints where the middleware's automatic validation does not apply.

The `ValidateRequestAsync` method checks for a valid anti-forgery token in the request headers (default header name: `RequestVerificationToken`). The token must:
- Be present in the request header
- Match the token bound to the current user's session
- Be compared using constant-time comparison

The call happens before any state-changing operation (line 27 in the original), so a request lacking a valid token will throw an `InvalidOperationException` and return a 400 error without processing the email change.

## Behaviour changes

- **New behaviour:** Requests to `POST /account/email` without a valid `RequestVerificationToken` header will be rejected with HTTP 400
- **Authenticated clients:** Must include the CSRF token in the request header (clients can obtain the token from a prior GET request or by including it in a form submission)
- **Cross-origin requests:** Will be blocked unless they include the valid CSRF token, preventing attackers from tricking authenticated users into changing their email via a crafted cross-origin POST
- **No impact on authorized behaviour:** Legitimate requests with valid tokens continue to work normally
