## Verdict

Exploitable (confidence: high). CWE-352 (Cross-Site Request Forgery) at `EmailEndpoints.cs:7`, the `app.MapPost("/account/email", ...)` handler.

## Source

A cross-site request forged against an authenticated victim's browser: an attacker-controlled page induces the victim's browser to send `POST /account/email` with a JSON body that binds to `EmailChangeRequest.Email`. `.RequireAuthorization()` confirms the caller carries a valid session/authentication cookie, but nothing in the handler or in `Program.cs` checks that the request actually originated from the application - the browser attaches the session cookie automatically regardless of the page that triggered the request. `builder.Services.AddAntiforgery()` in `Program.cs` registers the antiforgery service but nothing calls `app.UseAntiforgery()`, and even if it were called, this endpoint binds its body from JSON rather than a form, so the middleware would not enforce a token check on it. The tainted request reaches the sink unopposed at `EmailChangeService.QueueAsync(request.Email)` (`EmailEndpoints.cs:9`), which queues the account's email address for change.

## Fix

### File: EmailEndpoints.cs
```csharp
using Microsoft.AspNetCore.Antiforgery;

namespace Cases.Csrf;

public static class EmailEndpoints
{
    public static void Map(WebApplication app)
    {
        app.MapPost("/account/email", async (HttpContext context, EmailChangeRequest request, EmailChangeService service, IAntiforgery antiforgery) =>
        {
            await antiforgery.ValidateRequestAsync(context);
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

### File: Program.cs
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

## Explanation

No third-party library is involved - `IAntiforgery` and `ValidateRequestAsync` come from `Microsoft.AspNetCore.Antiforgery`, part of the ASP.NET Core shared framework already referenced by this project (via `AddAntiforgery()`), so there is no package/version to pin. `Program.cs` gains `app.UseAntiforgery()`, placed after `UseAuthentication()`/`UseAuthorization()` and before endpoint mapping as the framework requires, which wires the antiforgery middleware into the pipeline (previously registered as a service but never activated). That middleware alone only auto-validates form-bound minimal API endpoints, and this one binds its body from JSON, so `EmailEndpoints.cs` additionally takes `IAntiforgery` (resolved from DI, already registered by the pre-existing `AddAntiforgery()` call) and an explicit `HttpContext` parameter, and calls `await antiforgery.ValidateRequestAsync(context)` before the existing `QueueAsync` call. This enforces the `RequestVerificationToken` header check on every call: a legitimate same-origin client that has obtained and sent a valid token proceeds exactly as before; a forged cross-site request, which cannot produce that token, is rejected before `QueueAsync` runs.

Verification: copied both files into a scratch ASP.NET Core minimal-API project (SDK 10.0.203) and ran `dotnet build` - 0 errors, 0 warnings. This confirms `IAntiforgery`, `ValidateRequestAsync`, `AddAntiforgery`, `UseAntiforgery`, and the added minimal-API delegate parameters (`HttpContext`, `IAntiforgery`) all resolve and the file compiles as part of a working pipeline.

Assumption: any legitimate client currently calling this JSON endpoint (e.g. a same-origin SPA) will need to start sending the antiforgery header once this lands - typically by first calling a `GET` endpoint that returns `antiforgery.GetAndStoreTokens(context).RequestToken` and echoing it back as the `RequestVerificationToken` header on this call. No such client code appears in the case files, so this is noted rather than implemented.

## Behaviour changes

- Added `app.UseAntiforgery()` to `Program.cs`. Required for the antiforgery middleware to run at all; no other endpoints exist in this case to be affected by it.
- Added `HttpContext context` and `IAntiforgery antiforgery` parameters to the minimal API delegate in `EmailEndpoints.cs`. Required to call `ValidateRequestAsync`; `IAntiforgery` resolves from the DI container via the pre-existing `AddAntiforgery()` registration, so no new service registration was needed.
- Added `await antiforgery.ValidateRequestAsync(context)` immediately before the existing `await service.QueueAsync(request.Email)` call. On a missing or invalid antiforgery token this throws `AntiforgeryValidationException`; since neither the original nor the fixed `Program.cs` registers exception-handling middleware, a failed validation now surfaces as an unhandled exception resulting in a 500 response instead of the request silently succeeding. This is the intended effect of closing the weakness (a forged request is now rejected rather than processed), not a regression - a production deployment would typically pair this with `UseExceptionHandler` to return a controlled 400 instead, which is outside this fix's scope since no such middleware was present before.
- The success path is unchanged: a request that supplies a valid antiforgery token still reaches `QueueAsync(request.Email)` and returns `Results.Accepted()` exactly as before.
