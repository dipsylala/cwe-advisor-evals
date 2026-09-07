## Verdict
exploitable

## Source
HTTP POST request body received by the `/account/email` endpoint containing `EmailChangeRequest` JSON with `NewEmail` field (attacker-controlled via JSON deserialization).

## Sink
Line 27: `await accounts.UpdateEmailAsync(userId, request.NewEmail);` - state-changing operation on authenticated user's account without CSRF token validation.

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

    // Validate CSRF token before processing the request
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
This minimal API endpoint binds its body from JSON (`EmailChangeRequest`), which means `app.UseAntiforgery()` middleware does not enforce token validation - it only auto-validates endpoints that bind form data. The fix injects `IAntiforgery` into the handler and calls `await antiforgery.ValidateRequestAsync(context)` before processing the state-changing request. This enforces the antiforgery token check, requiring the client to provide a valid CSRF token in the `RequestVerificationToken` header. Without this validation, an attacker can craft a malicious website that tricks an authenticated user into changing their email address.

## Behaviour changes
none - The injected `IAntiforgery` dependency and the `ValidateRequestAsync()` call are purely defensive. If the token is invalid or missing, the middleware raises `AntiforgeryValidationException`, which ASP.NET Core converts to a 400 Bad Request response. The endpoint's return contract and success path remain unchanged; only invalid CSRF attempts are now rejected.
