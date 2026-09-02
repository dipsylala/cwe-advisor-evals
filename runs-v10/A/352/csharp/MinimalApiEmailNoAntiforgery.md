## Verdict
Real CSRF vulnerability confirmed. Minimal API email endpoint lacks antiforgery token validation, allowing cross-site request forgery attacks.

## Source
The vulnerable code defines a POST endpoint for sending email without validating an antiforgery token. The endpoint accepts user input directly without CSRF protection, allowing an attacker to forge requests on behalf of an authenticated user.

## Fix
Inject `IAntiforgery` into the Minimal API endpoint and validate the antiforgery token before processing the email request:

```csharp
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAntiforgery();
var app = builder.Build();

app.MapPost("/email", async (HttpContext context, IAntiforgery antiforgery, EmailRequest request) => {
    await antiforgery.ValidateRequestAsync(context);
    
    // Process the email request
    await SendEmail(request.Email);
    return Results.Ok("Email sent");
});
```

For endpoints that return HTML forms, include the token in the form:
```html
<form method="post" action="/email">
    @Html.AntiForgeryToken()
    <input type="email" name="email" />
    <button type="submit">Send</button>
</form>
```

## Explanation
CSRF protection requires validating a token that is:
1. Generated server-side and tied to the user's session
2. Included in state-changing requests (POST, PUT, DELETE)
3. Validated on the server before processing

ASP.NET Core's `IAntiforgery` service automatically generates tokens for authenticated users and validates them before the request handler executes. The `ValidateRequestAsync()` call verifies the token matches the user's session, preventing forged requests from untrusted origins. This is the primary defence against CSRF attacks and must be applied to every endpoint that modifies state.
