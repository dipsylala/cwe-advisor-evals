## Verdict
The Minimal API endpoint for deleting documents lacks authorization metadata. Anonymous and authenticated-but-unauthorized users can delete documents, violating CWE-862 (Missing Authorization).

## Source
File: Program.cs, line 30

The `app.MapDelete()` registration carries no `.RequireAuthorization()` call. Authorization in ASP.NET Core Minimal APIs is computed per endpoint from its own metadata, so the `[Authorize]` attributes on the MVC `DocumentsController` do not reach this separately registered route. The endpoint is reachable by anonymous callers.

## Fix

### File: Program.cs

```csharp
using DocumentPortal;
using DocumentPortal.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddAuthentication("Cookies").AddCookie("Cookies");

// NOTE: No FallbackPolicy is configured here, so any endpoint that carries no
// authorization metadata of its own (no [Authorize], no .RequireAuthorization())
// is reachable by anonymous callers.
builder.Services.AddAuthorization();

builder.Services.AddScoped<IDocumentService, DocumentService>();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// MVC controllers (DocumentsController) are correctly protected with [Authorize]
// on every action. This route table is fine.
app.MapControllers();

// Newer feature: a Minimal API endpoint added alongside the controller-based API.
// [Authorize] on DocumentsController does not reach this separately registered
// route - authorization metadata is computed per endpoint, and this endpoint
// carries none: no [Authorize], no .RequireAuthorization(), nothing.
app.MapDelete("/api/documents/{id}", DocumentEndpoints.DeleteDocument)
    .RequireAuthorization();

app.Run();
```

## Explanation
The fix adds `.RequireAuthorization()` as a call chain method on the endpoint registration, attaching an authorization requirement as endpoint metadata. This requires the caller to be authenticated before the handler executes. `RequireAuthorization()` without arguments applies the `DefaultPolicy`, which requires an authenticated user. Since a delete operation is a state-changing sensitive action, this authorization check must run server-side before the handler. For scenarios requiring resource-level ownership verification (confirming the caller owns the specific document being deleted), that check would be implemented inside the handler via `IAuthorizationService.AuthorizeAsync()` in a resource-based authorization handler.

## Behaviour changes
- **Unauthenticated requests**: `DELETE /api/documents/{id}` from anonymous users now receives 401 Unauthorized from the authorization middleware before the handler executes; previously they reached the handler.
- **Authenticated requests**: Callers with valid authentication continue to the handler and receive its normal response (200, 204, 404, etc.); no change.
- **Endpoint exposure**: The handler is no longer invokable without authentication, closing the authorization bypass for this sensitive operation.
