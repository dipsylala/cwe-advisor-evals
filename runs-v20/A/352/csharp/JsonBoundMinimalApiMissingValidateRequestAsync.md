## Verdict

Confirmed. `POST /account/email` changes the authenticated user's email based solely on the cookie session; nothing on this endpoint ties the request to a token only the legitimate origin could have supplied. `AddAntiforgery()`/`UseAntiforgery()` register the antiforgery services and middleware, but for Minimal APIs that middleware does not automatically validate anything for a JSON-bound endpoint - ASP.NET Core's automatic antiforgery enforcement only fires for endpoints that carry form-binding metadata. A JSON `[FromBody]` handler like this one is never covered by it, so the endpoint accepts a cross-site POST (cookie auth attaches automatically, JSON can be sent with `Content-Type: text/plain` to avoid a CORS preflight) and silently changes the account email.

## Source

`request.NewEmail`, bound from the JSON request body of `POST /account/email`, flowing directly into `accounts.UpdateEmailAsync(userId, request.NewEmail)` with no antiforgery check anywhere on the path.

## Fix

### File: Program.cs
```csharp
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie();
builder.Services.AddAuthorization();
builder.Services.AddAntiforgery(options =>
{
    // JSON clients cannot submit a hidden form field, so accept the token via header.
    options.HeaderName = "X-CSRF-TOKEN";
});
builder.Services.AddScoped<AccountService>();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

// Lets an authenticated client fetch a token bound to its session before calling
// the mutating endpoint below. The token is safe to hand back in the response body
// because it is single-use verification material, not a secret credential.
app.MapGet("/account/csrf-token", (IAntiforgery antiforgery, HttpContext context) =>
{
    var tokens = antiforgery.GetAndStoreTokens(context);
    return Results.Ok(new { token = tokens.RequestToken });
}).RequireAuthorization();

app.MapPost("/account/email", async (EmailChangeRequest request, AccountService accounts, IAntiforgery antiforgery, HttpContext context) =>
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
        return Results.BadRequest("Missing or invalid antiforgery token.");
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

`UseAntiforgery()` only auto-validates requests to endpoints that are marked as accepting form data; a Minimal API endpoint bound from JSON (`[FromBody]`/implicit body binding, no `IFormCollection`/`[FromForm]`) carries no such metadata, so the middleware passes every request through untouched regardless of how the services were registered. The fix injects `IAntiforgery` directly into the handler and calls `ValidateRequestAsync(context)` before performing the mutation, which is the documented way to protect a Minimal API that doesn't use form binding. A failed validation throws `AntiforgeryValidationException`, which is caught and turned into a `400` rather than letting the request proceed.

Because the endpoint consumes JSON rather than a form post, the antiforgery token cannot travel as a hidden form field, so `AntiforgeryOptions.HeaderName` is set to `X-CSRF-TOKEN` and the client is expected to send the token in that header (`ValidateRequestAsync` checks the configured header when it is set, in addition to the form field). A companion `GET /account/csrf-token` endpoint is added so an authenticated client has a way to obtain a token scoped to its own session via `GetAndStoreTokens` before calling the mutating endpoint - without an issuing endpoint, no legitimate client could ever produce a valid token to send. Both endpoints keep `RequireAuthorization()` so the token-issuing endpoint itself cannot be used to enumerate or probe unauthenticated.

This defense works because the antiforgery token is generated per-user-session and tied to the authentication cookie; a cross-site page can cause the browser to attach the victim's session cookie automatically, but it has no way to read the token value (same-origin policy blocks it from fetching `/account/csrf-token` and reading the response), so it cannot supply a valid `X-CSRF-TOKEN` header alongside the forged request.
