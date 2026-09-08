## Verdict

Confirmed. `POST /account/email` in `EmailEndpoints.cs` changes the authenticated user's email address based solely on cookie-derived authentication (`RequireAuthorization()` + `UseAuthentication()`/`UseAuthorization()` in `Program.cs`). The endpoint reads a JSON body with no antiforgery check, so a cross-site request (an attacker page issuing `fetch`/form POST with `credentials: include` or a same-site cookie sent automatically) can trigger the email change using the victim's session, with no way for the server to tell the request originated from the attacker's site. `Program.cs` already calls `builder.Services.AddAntiforgery()`, registering the antiforgery system, but nothing in the request pipeline or the endpoint validates a token, so the registration has no effect.

## Source

`E:/Github/cwe-advisor/evals/cases/352/csharp/MinimalApiEmailNoAntiforgery/EmailEndpoints.cs`, line 7 - the `app.MapPost("/account/email", ...)` handler - is the unprotected state-changing sink. `Program.cs` is the second file in the call chain: it wires up authentication/authorization and registers the antiforgery service but never enforces it.

## Fix

### File: EmailEndpoints.cs
```csharp
namespace Cases.Csrf;

public static class EmailEndpoints
{
    public static void Map(WebApplication app)
    {
        app.MapPost("/account/email", async (
            EmailChangeRequest request,
            EmailChangeService service,
            Microsoft.AspNetCore.Antiforgery.IAntiforgery antiforgery,
            HttpContext httpContext) =>
        {
            try
            {
                await antiforgery.ValidateRequestAsync(httpContext);
            }
            catch (Microsoft.AspNetCore.Antiforgery.AntiforgeryValidationException)
            {
                return Results.BadRequest("Invalid or missing antiforgery token.");
            }

            await service.QueueAsync(request.Email);
            return Results.Accepted();
        }).RequireAuthorization();

        app.MapGet("/account/email/antiforgery-token", (
            Microsoft.AspNetCore.Antiforgery.IAntiforgery antiforgery,
            HttpContext httpContext) =>
        {
            var tokens = antiforgery.GetAndStoreTokens(httpContext);
            return Results.Ok(new { token = tokens.RequestToken });
        }).RequireAuthorization();
    }
}

public sealed record EmailChangeRequest(string Email);

public sealed class EmailChangeService
{
    public System.Threading.Tasks.Task QueueAsync(string email)
    {
        return System.Threading.Tasks.Task.CompletedTask;
    }
}
```

## Explanation

`AddAntiforgery()` only registers the antiforgery token services in the container - it does not, by itself, protect any endpoint. ASP.NET Core's built-in automatic antiforgery validation (the `IAntiforgeryMetadata`/`UseAntiforgery()` middleware behavior added in .NET 8) only kicks in for endpoints that bind form data (`[FromForm]`/`IFormCollection`); this endpoint binds `EmailChangeRequest` from the JSON body, so it is never covered automatically and must validate explicitly.

The fix injects `IAntiforgery` and calls `ValidateRequestAsync(HttpContext)` inside the handler before performing the state change. This requires the caller to present a valid antiforgery token (by convention sent in a request header such as `X-XSRF-TOKEN`, matched against the antiforgery cookie) alongside the authentication cookie. A cross-site request from an attacker's page can cause the browser to attach the victim's auth cookie automatically, but the attacker has no way to read or forge the paired antiforgery token, so `ValidateRequestAsync` throws `AntiforgeryValidationException` and the request is rejected with `400 Bad Request` instead of reaching `EmailChangeService.QueueAsync`.

A companion `GET /account/email/antiforgery-token` endpoint is added so the legitimate client-side application (which cannot otherwise obtain a fresh token for a pure JSON API with no server-rendered form) can fetch a valid token via `antiforgery.GetAndStoreTokens()` and echo it back in the header on the subsequent `POST`. This endpoint is a safe read that only issues a token tied to the caller's own authenticated session; it does not perform the state change and does not weaken the check on the `POST` route. No change to `Program.cs` is needed: `AddAntiforgery()` is already registered, and `UseAuthentication()`/`UseAuthorization()` continue to run as before.
