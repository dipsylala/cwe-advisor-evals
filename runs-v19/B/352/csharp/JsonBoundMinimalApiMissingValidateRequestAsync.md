## Verdict

Exploitable.

## Source

Attacker-controlled HTTP POST request to `/account/email` endpoint with JSON-bound body `EmailChangeRequest`. The `NewEmail` field flows through to a state-changing operation without CSRF token validation.

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

The vulnerability occurs because the endpoint is a minimal API that binds its body from JSON (`EmailChangeRequest request`). Although `app.UseAntiforgery()` middleware is enabled, it only automatically validates endpoints that bind form data (`IFormCollection`, `IFormFile`, `[FromForm]`). For JSON-bound endpoints, the middleware records the validation check but does not enforce it. The fix injects the `IAntiforgery` service as a parameter and calls `await antiforgery.ValidateRequestAsync(context)` at the start of the handler, before any state-changing operation. This enforces CSRF token validation for JSON-bound requests by checking the `RequestVerificationToken` header (the default header name) against the token bound to the session, rejecting any request with a missing or invalid token.

## Behaviour changes

Added `IAntiforgery antiforgery` parameter to the handler lambda: This is a dependency-injected service provided by ASP.NET Core's antiforgery system and has no side effects beyond enabling the validation call. Added `await antiforgery.ValidateRequestAsync(context);` before the state-changing operation: This call enforces CSRF token validation for the JSON-bound endpoint. If the token is invalid or missing, `ValidateRequestAsync` throws an `AntiforgeryValidationException`, which is caught by ASP.NET Core's exception handling middleware and returns a 400 Bad Request response. This is the intended behavior - rejecting unauthenticated requests is the security requirement. The call does not alter the return value, arguments to downstream calls, or other logic flow when validation succeeds.
