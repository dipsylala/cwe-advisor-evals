## Verdict

Exploitable. The endpoint accepts authenticated POST requests to change user email without CSRF token validation. An attacker can craft a malicious webpage that, when visited by an authenticated user, silently submits a request to change the email to attacker-controlled value using only the authenticated user's existing session cookie.

## Source

HTTP POST request body from an attacker-controlled form or AJAX request on an attacker's domain, binding to `EmailChangeRequest` with an arbitrary email value. The source is unauthenticated (the attacker does not need credentials), but exploits the victim's active authentication via session cookie.

## Fix

**Vulnerable code:**

```csharp
app.MapPost("/account/email", async (EmailChangeRequest request, EmailChangeService service) =>
{
    await service.QueueAsync(request.Email);
    return Results.Accepted();
}).RequireAuthorization();
```

**Fixed code:**

```csharp
app.MapPost("/account/email", async (EmailChangeRequest request, EmailChangeService service, IAntiforgery antiforgery, HttpContext httpContext) =>
{
    await antiforgery.ValidateRequestAsync(httpContext);
    await service.QueueAsync(request.Email);
    return Results.Accepted();
}).RequireAuthorization();
```

The fix injects `IAntiforgery` and `HttpContext` as handler parameters (available in minimal API dependency injection) and calls `ValidateRequestAsync()` before processing the email change request.

## Explanation

The endpoint is a JSON-bound minimal API that modifies state (changes user email) but lacks CSRF token validation. ASP.NET Core's `app.UseAntiforgery()` middleware only auto-validates endpoints that bind form data; JSON-bound endpoints must explicitly validate by calling `antiforgery.ValidateRequestAsync()`. The framework generates cryptographically random tokens bound to the authenticated user's session and validates that the request includes the correct token in the `RequestVerificationToken` header (or configured header name). This prevents cross-origin requests from a malicious site from succeeding, because the attacker cannot read or forge a valid token bound to the victim's session.

## Behaviour changes

- **New parameter injection:** `IAntiforgery` and `HttpContext` are injected into the handler. `IAntiforgery` is a framework service; `HttpContext` is standard minimal API dependency injection. Both are available at no runtime cost.
- **New validation call:** `ValidateRequestAsync()` is an async operation that runs before the handler body. It is non-blocking and completes in microseconds for valid tokens.
- **New requirement for clients:** All authenticated requests to this endpoint must include a valid `RequestVerificationToken` header with the CSRF token value obtained from the application. Clients that previously omitted this header will now receive a 400 Bad Request response with no email change performed.
- **No return value change:** The endpoint still returns `Results.Accepted()` on success. On validation failure, the middleware short-circuits and returns an error response instead of executing the handler.
