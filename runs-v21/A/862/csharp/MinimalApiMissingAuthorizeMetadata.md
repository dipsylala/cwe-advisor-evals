## Verdict

CONFIRMED. The endpoint registered at line 30 lacks authorization metadata. In Minimal APIs, authorization metadata is computed per endpoint. The [Authorize] attribute on DocumentsController does not apply to separately registered routes. The MapDelete call chains no .RequireAuthorization() and carries no other authorization guard.

## Source

File: Program.cs, line 30

```csharp
app.MapDelete("/api/documents/{id}", DocumentEndpoints.DeleteDocument);
```

The DeleteDocument handler deletes a document by ID (DocumentEndpoints.cs, line 7-16), a sensitive operation requiring authorization. However, the endpoint is registered without any authorization requirement.

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
// SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
app.MapDelete("/api/documents/{id}", DocumentEndpoints.DeleteDocument).RequireAuthorization();

app.Run();
```

## Explanation

Minimal APIs compute authorization metadata independently for each registered endpoint. The [Authorize] attribute on DocumentsController only protects actions in that controller; it does not extend to separately registered routes.

The MapDelete call at line 30 registers a delete endpoint without calling .RequireAuthorization() or any other authorization guard. An unauthenticated caller can reach this endpoint and delete documents.

The fix chains .RequireAuthorization() after MapDelete. This applies the authorization policy to the specific endpoint, matching the control applied to DocumentsController actions. The endpoint now requires authentication and authorization before allowing document deletion.
