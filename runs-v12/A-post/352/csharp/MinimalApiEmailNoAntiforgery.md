## Verdict

**Confirmed: CWE-352 (Cross-Site Request Forgery)**

The POST endpoint that changes user email is protected against unauthorized access via `RequireAuthorization()`, but lacks CSRF token validation. An attacker can exploit this by crafting a malicious webpage that performs an email change request on behalf of an authenticated user.

## Source

**EmailEndpoints.cs, line 7-11:**
```csharp
app.MapPost("/account/email", async (EmailChangeRequest request, EmailChangeService service) =>
{
    await service.QueueAsync(request.Email);
    return Results.Accepted();
}).RequireAuthorization();
```

**Program.cs, line 4 & 7-8:**
The antiforgery service is registered (`AddAntiforgery()`) but the middleware is not activated (`UseAntiforgery()` is missing).

## Fix

**Program.cs:** Add the antiforgery middleware after authorization:
```csharp
var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();  // ADD THIS LINE

EmailEndpoints.Map(app);
```

**EmailEndpoints.cs:** Add CSRF token validation to the endpoint:
```csharp
app.MapPost("/account/email", async (EmailChangeRequest request, EmailChangeService service) =>
{
    await service.QueueAsync(request.Email);
    return Results.Accepted();
}).RequireAuthorization()
  .RequireAntiforgeryToken();  // ADD THIS LINE
```

## Explanation

State-changing operations (POST, PUT, DELETE) must be protected against CSRF attacks. ASP.NET Core's antiforgery system prevents these by:

1. **Generating tokens:** `UseAntiforgery()` middleware generates request-specific tokens and includes them in responses.
2. **Validating tokens:** `RequireAntiforgeryToken()` ensures the endpoint rejects requests missing a valid token.

Without this protection, a cross-origin attacker can forge an email-change request. When a logged-in user visits the attacker's website, their browser automatically sends authentication cookies, but the missing token prevents the forged request from succeeding.

Authentication alone (`RequireAuthorization()`) is insufficient—it only verifies the user's identity, not the legitimacy of the request itself.
