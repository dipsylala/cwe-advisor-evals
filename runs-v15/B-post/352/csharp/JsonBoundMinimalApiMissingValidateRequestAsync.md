## Verdict

CSRF vulnerability confirmed. The endpoint accepts state-changing requests (email update) over POST without verifying request authenticity via CSRF token validation.

## Source

HTTP POST request from client with JSON body containing `EmailChangeRequest.NewEmail`. The request originates from line 18 endpoint handler that accepts user-supplied email address to update user account state.

## Fix

Add CSRF token validation to the JSON-bound minimal API endpoint. Inject `IAntiforgery` and call `ValidateRequestAsync()` before processing the request:

```csharp
app.MapPost("/account/email", async (EmailChangeRequest request, AccountService accounts, HttpContext context, IAntiforgery antiforgery) =>
{
    await antiforgery.ValidateRequestAsync(context);
    
    var userId = context.User.FindFirst("sub")?.Value;
    if (userId is null)
    {
        return Results.Unauthorized();
    }

    await accounts.UpdateEmailAsync(userId, request.NewEmail);
    return Results.Accepted();
}).RequireAuthorization();
```

## Explanation

The endpoint is a minimal API that binds JSON from the request body. ASP.NET Core's `app.UseAntiforgery()` middleware (line 16) does not enforce token validation for JSON-bound endpoints—it only auto-validates form-bound endpoints. For JSON-bound minimal APIs, explicit validation via `IAntiforgery.ValidateRequestAsync()` is required. This call checks the CSRF token passed in the `RequestVerificationToken` header (the default header name) against the token bound to the authenticated user's session. The validation enforces constant-time comparison and prevents unauthenticated cross-site requests from succeeding.

The framework injects `IAntiforgery` automatically; no additional configuration or dependency is required.

## Behaviour changes

- The endpoint now requires clients to send a valid CSRF token in the `RequestVerificationToken` header alongside the POST request.
- Requests without a valid token are rejected with HTTP 400 Bad Request.
- Legitimate clients (SPA, mobile apps, form submissions) must retrieve the token before submitting changes and include it in the header.
- No change to successful request processing or response structure when token is valid.
