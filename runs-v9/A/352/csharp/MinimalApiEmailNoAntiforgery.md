## Verdict

Confirmed. `POST /account/email` is a state-changing, cookie/session-authenticated endpoint with no CSRF defense: the application registers `AddAntiforgery()` in `Program.cs` but never calls `UseAntiforgery()`, and the endpoint itself never validates an antiforgery token before queuing the email change. Any authenticated user's browser can be induced (via a cross-site auto-submitting form or fetch) to issue this request, and the browser will attach the session cookie automatically, letting an attacker change the victim's account email.

## Source

- `EmailEndpoints.cs:7-11` - `app.MapPost("/account/email", ...)` handler, gated only by `.RequireAuthorization()`. Authorization confirms *who* is logged in but does nothing to confirm the request originated from the application's own UI, so it does not address CSRF.
- `EmailEndpoints.cs:9` - `await service.QueueAsync(request.Email)` is the state-changing sink: it queues an account email change using attacker-controlled `request.Email` with no origin/token check upstream.
- `Program.cs:4` - `builder.Services.AddAntiforgery()` registers the antiforgery system but is never paired with `app.UseAntiforgery()` or a per-endpoint validation call, so the registration is inert.

## Fix

`Program.cs` - add the antiforgery middleware after authentication/authorization and before endpoint mapping:

```csharp
using Cases.Csrf;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAntiforgery();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

EmailEndpoints.Map(app);

app.Run();
```

`EmailEndpoints.cs` - explicitly validate the antiforgery token inside the handler (minimal API JSON endpoints are not auto-validated by the antiforgery middleware the way MVC form posts are, so validation must be called explicitly), and expose a token-issuing endpoint the client uses to obtain the token before submitting the change:

```csharp
namespace Cases.Csrf;

public static class EmailEndpoints
{
    public static void Map(WebApplication app)
    {
        app.MapGet("/account/email/csrf-token", (HttpContext context, IAntiforgery antiforgery) =>
        {
            var tokens = antiforgery.GetAndStoreTokens(context);
            return Results.Ok(new { token = tokens.RequestToken });
        }).RequireAuthorization();

        app.MapPost("/account/email", async (
            HttpContext context,
            IAntiforgery antiforgery,
            EmailChangeRequest request,
            EmailChangeService service) =>
        {
            try
            {
                await antiforgery.ValidateRequestAsync(context);
            }
            catch (AntiforgeryValidationException)
            {
                return Results.StatusCode(StatusCodes.Status403Forbidden);
            }

            await service.QueueAsync(request.Email);
            return Results.Accepted();
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

The client fetches `/account/email/csrf-token` first, then sends the returned token back on the `POST` as the `X-CSRF-TOKEN` header (ASP.NET Core's default antiforgery header name, configurable via `AntiforgeryOptions.HeaderName`); `ValidateRequestAsync` checks that header token against the antiforgery cookie ASP.NET Core sets alongside it. A cross-site page can trigger the cookie-authenticated `POST`, but it cannot read the token endpoint's JSON response (blocked by same-origin policy) or forge a matching header value, so the forged request fails validation.

## Explanation

ASP.NET Core's antiforgery system works by pairing a cookie (sent automatically by the browser, including cross-site) with a second token that must be supplied out-of-band - as a form field or, for APIs, a custom header - which a cross-site attacker cannot read or reproduce because of same-origin restrictions. `AddAntiforgery()` only registers the services; without `UseAntiforgery()` in the middleware pipeline and an explicit `ValidateRequestAsync` (or equivalent) call in the handler, no token is ever checked, so the registration was a no-op. `.RequireAuthorization()` is unrelated to this gap: it verifies the caller has a valid identity, but a forged cross-site request rides on the victim's own authenticated session cookie, so authorization passes on a forged request just as easily as on a legitimate one. Minimal API endpoints that accept JSON bodies (rather than form posts) are not automatically covered by the antiforgery middleware's implicit validation, so the token must be validated explicitly inside the handler, as done above, rather than relying on middleware alone.
