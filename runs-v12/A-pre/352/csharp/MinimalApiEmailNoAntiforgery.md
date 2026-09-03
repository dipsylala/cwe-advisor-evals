## Verdict

**CONFIRMED**: This is a genuine CWE-352 (Cross-Site Request Forgery) vulnerability. The POST endpoint for changing a user's email accepts requests without validating an antiforgery token, allowing an attacker to forge email change requests on behalf of authenticated users.

## Source

**EmailEndpoints.cs, line 7-11**: The `MapPost` endpoint for `/account/email` processes state-changing requests (changing the user's email) without any CSRF token validation.

**Root cause**: The application registers the antiforgery service in Program.cs (`builder.Services.AddAntiforgery()`) but never invokes the antiforgery middleware (`app.UseAntiforgery()`). Without the middleware, no CSRF token validation occurs on any request.

**Attack scenario**: An attacker crafts a hidden form or API request targeting `/account/email` and tricks an authenticated user into submitting it. Since no antiforgery token is required, the request succeeds and changes the user's email address without their knowledge or consent.

## Fix

**In Program.cs**, add the antiforgery middleware after authorization:

```csharp
using Cases.Csrf;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAntiforgery();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();  // Add this line

EmailEndpoints.Map(app);

app.Run();
```

## Explanation

The antiforgery middleware must be invoked in the request pipeline to validate tokens on POST, PUT, PATCH, and DELETE requests. Adding `app.UseAntiforgery()` after authorization ensures that:

1. **Token generation**: The middleware generates and includes an antiforgery token in responses (cookies and form fields).
2. **Token validation**: Incoming requests that modify state are checked for a valid antiforgery token before processing.
3. **Automatic protection**: Minimal API endpoints automatically enforce the validation without requiring per-endpoint attributes.

With this middleware in place, the POST to `/account/email` will reject requests lacking a valid antiforgery token, preventing CSRF attacks while legitimate requests carrying the token succeed.
