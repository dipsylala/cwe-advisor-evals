## Verdict

**CWE-352 (Cross-Site Request Forgery) - exploitable.** Confidence: high.

`POST /account/email` is a state-changing minimal API endpoint protected only by `RequireAuthorization()`. Authorization confirms the caller carries a valid session cookie; it says nothing about where the request originated. `Program.cs` calls `builder.Services.AddAntiforgery()` but never adds the `app.UseAntiforgery()` middleware to the pipeline, so no antiforgery check runs at all. A cross-site page that submits a same-site cookie-carrying request (e.g. a background `fetch` with `credentials: "include"`, or an auto-submitting form) reaches the handler and queues an email change for the victim's authenticated account.

## Source

The HTTP request body to `POST /account/email`, submitted cross-site from an attacker-controlled page while the victim's authenticated session cookie is attached by the browser. Bound in the handler as `EmailChangeRequest request` (`EmailEndpoints.cs`, line 7).

## Fix

**Vulnerable - `EmailEndpoints.cs`:**

```csharp
namespace Cases.Csrf;

public static class EmailEndpoints
{
    public static void Map(WebApplication app)
    {
        app.MapPost("/account/email", async (EmailChangeRequest request, EmailChangeService service) =>
        {
            // No origin/authenticity check - only authentication is enforced.
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

**Vulnerable - `Program.cs`:**

```csharp
using Cases.Csrf;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAntiforgery();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
// app.UseAntiforgery() is missing - AddAntiforgery() registered the service but nothing activates it.

EmailEndpoints.Map(app);

app.Run();
```

**Fixed - `Program.cs`:**

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

**Fixed - `EmailEndpoints.cs`:**

```csharp
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

## Explanation

Two gaps combine to leave this endpoint unprotected, and both have to close together. First, `app.UseAntiforgery()` was never added to the pipeline, so the antiforgery service registered by `AddAntiforgery()` was never wired into request handling - adding it, after `UseAuthentication`/`UseAuthorization` and before endpoint mapping, is the prerequisite for any validation to run. Second, `app.UseAntiforgery()` on its own only auto-validates minimal API endpoints that bind form data; this handler binds `EmailChangeRequest` from the JSON body, which the middleware does not inspect or reject on a missing token. Closing that requires injecting `IAntiforgery` directly into the handler and calling `await antiforgery.ValidateRequestAsync(context)` before the state-changing call. Together this restores the check `[ValidateAntiForgeryToken]` would provide for an MVC controller action but that minimal APIs do not get automatically: the caller must now present a valid `RequestVerificationToken` header (ASP.NET Core's default `AntiforgeryOptions.HeaderName`) bound to the authenticated user's antiforgery cookie, which a cross-site page cannot forge or read due to same-origin restrictions.

## Behaviour changes

- `app.UseAntiforgery()` added to the middleware pipeline in `Program.cs`. This activates the already-registered antiforgery service; with only one endpoint mapped in this codebase, it has no effect beyond enabling the check added below.
- `HttpContext context` and `IAntiforgery antiforgery` added as handler parameters, and `await antiforgery.ValidateRequestAsync(context)` added as the first line of the handler, before `QueueAsync`. This is the core of the fix, not incidental: a request that omits a valid antiforgery token now throws `AntiforgeryValidationException` (translated to a 400 response by the framework) instead of reaching `QueueAsync`. A legitimate same-origin caller must now send the `RequestVerificationToken` header sourced from the antiforgery cookie pair; this is the intended new requirement, not a regression.
- No other change: `RequireAuthorization()`, the route, the request/response shape, and `QueueAsync`'s signature and return value are all unchanged.

**Assumption:** the endpoint's JSON body binding (`EmailChangeRequest` bound as a POCO, not `[FromForm]`/`IFormCollection`) was read from the parameter type in `EmailEndpoints.cs`, which is the documented case where `app.UseAntiforgery()` alone does not enforce the check - hence the added explicit `ValidateRequestAsync` call rather than relying on the middleware alone.
