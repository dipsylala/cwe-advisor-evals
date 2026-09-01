## Verdict
Exploitable. The endpoint at line 7 is a state-changing POST operation that requires authentication but lacks CSRF token validation. An attacker can craft a cross-origin request that an authenticated user's browser will automatically execute, allowing unauthorized email changes on behalf of the victim.

## Source
Client request: An attacker-crafted POST request to `/account/email` containing a malicious email address, submitted via a cross-origin context (e.g., a link on an attacker's site that a logged-in user visits).

## Fix
The endpoint code at line 7 can remain structurally unchanged, but anti-forgery protection must be enabled in the application's startup configuration. The vulnerability exists because ASP.NET Core's `UseAntiforgery()` middleware is not registered in the request pipeline.

**Vulnerable endpoint code (line 7):**
```csharp
app.MapPost("/account/email", async (EmailChangeRequest request, EmailChangeService service) =>
{
    await service.QueueAsync(request.Email);
    return Results.Accepted();
}).RequireAuthorization();
```

**Required startup configuration (Program.cs or Startup.cs):**

Add the antiforgery service during configuration:
```csharp
services.AddAntiforgery();
```

Add the antiforgery middleware to the pipeline, placed after authentication and authorization but before endpoint mapping:
```csharp
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();  // Critical fix: must be present for minimal APIs
app.MapEndpoints();    // or app.MapGroup(...).Map...()
```

**Client-side requirement:**
The client must include the anti-forgery token in the request header. By default, ASP.NET Core expects the header name `RequestVerificationToken`:
```javascript
fetch('/account/email', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'RequestVerificationToken': tokenValue  // Token obtained from the application
    },
    body: JSON.stringify({ email: 'new@example.com' })
});
```

## Explanation
Minimal API endpoints in ASP.NET Core are not protected by the MVC `[ValidateAntiForgeryToken]` attribute or the `AutoValidateAntiforgeryTokenAttribute` filter. Instead, they require the `app.UseAntiforgery()` middleware to be explicitly registered in the request pipeline. Without this middleware, state-changing endpoints accept requests from any origin, enabling CSRF attacks where an attacker tricks an authenticated user's browser into performing unwanted actions. The fix ensures that all POST/PUT/DELETE/PATCH requests to protected endpoints include a cryptographically valid anti-forgery token that was issued by the server and bound to the user's session, preventing cross-origin request forgery.

## Behaviour changes
None. The middleware validation is transparent to the endpoint code. The endpoint continues to receive and process requests identically, except that invalid or missing tokens are rejected by the middleware before reaching the handler. The only observable change is that clients must now supply a valid anti-forgery token in the request header, and requests without one will receive a 400 Bad Request response from the middleware.
