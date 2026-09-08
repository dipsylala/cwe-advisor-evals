## Verdict

exploitable

- **cwe_id**: CWE-352 (Cross-Site Request Forgery)
- **location**: `Program.cs`, line 27 (the `accounts.UpdateEmailAsync(...)` call inside the `POST /account/email` handler)
- **confidence**: high

## Source

The JSON request body deserialized into `EmailChangeRequest` (specifically `request.NewEmail`) by minimal API model binding on `POST /account/email`. The endpoint is reachable by any authenticated browser session because authentication is cookie-based (`AddCookie()`), and a cookie is attached automatically by the browser to a cross-site request - the application has no independent proof that the request originated from its own UI.

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

    try
    {
        await antiforgery.ValidateRequestAsync(context);
    }
    catch (AntiforgeryValidationException)
    {
        return Results.BadRequest("Invalid or missing antiforgery token.");
    }

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

The handler binds its body from JSON (`EmailChangeRequest`), and `app.UseAntiforgery()` only auto-enforces the antiforgery check for minimal API endpoints that bind form data (`IFormCollection`/`IFormFile`/`[FromForm]`); a JSON-bound endpoint passes through that middleware with the check recorded but not enforced, so the state-changing email update executes for any authenticated cross-site request carrying the session cookie. The fix injects the already-registered `IAntiforgery` service into the handler and calls `await antiforgery.ValidateRequestAsync(context)` before the sink, which requires the request to carry a valid antiforgery token (by default in the `RequestVerificationToken` header, matching `AntiforgeryOptions.HeaderName`) bound to the authenticated user's claims. A legitimate same-origin client that has fetched the token pair from the antiforgery service passes; a forged cross-site request, which cannot obtain or read that token due to the browser's same-origin policy, fails validation and is rejected before `UpdateEmailAsync` runs. `ValidateRequestAsync` throws `AntiforgeryValidationException` on failure, so the call is wrapped in a `try`/`catch` that returns `400 Bad Request` instead of letting the exception surface as an unhandled server error.

## Behaviour changes

- Requests that previously always reached `UpdateEmailAsync` (given a valid session and authenticated `userId`) now additionally require a valid antiforgery token in the request; a request missing or carrying an invalid token now receives `400 Bad Request` instead of `202 Accepted`. This is the intended effect of closing the CSRF weakness, not a side effect.
- A legitimate client (the application's own front end) must now obtain the antiforgery token pair (via `IAntiforgery.GetAndStoreTokens` or an endpoint that surfaces it) and send the request token back in the `RequestVerificationToken` header on this call; without that change on the client side, previously-working legitimate requests will also start failing with `400 Bad Request`. This is a required, disclosed integration change, not an unnoticed regression.
- No other arguments, return values, or discarded output changed: `UpdateEmailAsync(userId, newEmail)` is called with the same two values as before, `Results.Accepted()` is still returned on success, and the pre-existing `Results.Unauthorized()` check is untouched.

**Verification**: The fixed file was copied into a scratch ASP.NET Core minimal-API project (`dotnet new web`, .NET 10 SDK) referencing the same `Microsoft.AspNetCore.Antiforgery` and `Microsoft.AspNetCore.Authentication.Cookies` namespaces, and built with `dotnet build`. Result: `Build succeeded. 0 Warning(s), 0 Error(s)` - confirming `IAntiforgery`, `AntiforgeryValidationException`, and minimal-API DI parameter binding for the new `IAntiforgery antiforgery` parameter all resolve correctly.
