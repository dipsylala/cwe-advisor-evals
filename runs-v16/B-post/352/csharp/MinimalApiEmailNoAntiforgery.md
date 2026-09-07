## Verdict

Exploitable. The POST endpoint at line 7 processes state-changing requests (email modification) from authenticated users without validating CSRF tokens. An attacker can trick an authenticated user into visiting a malicious page that submits a cross-origin POST to `/account/email`, causing the victim to change their own email address.

## Source

The `EmailChangeRequest` parameter bound from the request body in the `/account/email` POST handler. The request body comes directly from the client without CSRF token verification.

## Fix

**Vulnerable code (EmailEndpoints.cs, lines 7-12):**
```csharp
app.MapPost("/account/email", async (EmailChangeRequest request, EmailChangeService service) =>
{
    await service.QueueAsync(request.Email);
    return Results.Accepted();
}).RequireAuthorization();
```

**Fixed code (EmailEndpoints.cs):**
```csharp
app.MapPost("/account/email", async (EmailChangeRequest request, EmailChangeService service, HttpContext context, IAntiforgery antiforgery) =>
{
    await antiforgery.ValidateRequestAsync(context);
    await service.QueueAsync(request.Email);
    return Results.Accepted();
}).RequireAuthorization();
```

**Additional fix required (Program.cs, add after `app.UseAuthorization();`):**
```csharp
app.UseAntiforgery();
```

## Explanation

The minimal API endpoint binds `EmailChangeRequest` from the JSON request body, making it a JSON-bound endpoint. Per ASP.NET Core's CSRF protection model, `app.UseAntiforgery()` middleware only auto-validates form-bound endpoints; JSON-bound endpoints must explicitly validate the token by injecting `IAntiforgery` and calling `ValidateRequestAsync(context)`. The antiforgery middleware, when placed after authorization in the pipeline, checks that the incoming request includes a valid token that matches the user's session, preventing attackers from forging requests on behalf of authenticated users. The fix injects both the `HttpContext` (required to access request headers and cookies) and the `IAntiforgery` service into the handler, then validates the token before processing the email change.

## Behaviour changes

- **Added parameters**: The handler now receives `HttpContext context` and `IAntiforgery antiforgery` via dependency injection. These are framework-provided services with no side effects on handler invocation.
- **Added validation call**: `await antiforgery.ValidateRequestAsync(context)` is called before processing, which throws an exception if the token is missing or invalid. This replaces the absence of validation with active enforcement.
- **Middleware addition**: `app.UseAntiforgery()` in the middleware pipeline runs before the endpoint is reached, but does not reject JSON-bound endpoints unless the explicit `ValidateRequestAsync` call is present. Its addition enables the framework to track antiforgery state; the explicit call in the handler enforces validation.
- **No return value or output change**: The endpoint still returns `Results.Accepted()` on success; on token validation failure, the middleware throws an exception that produces a 400 Bad Request response.

All changes preserve the original endpoint's contract: it still requires authorization, still accepts the same request shape, and still queues the email. The only alteration is the addition of security validation before state modification.
