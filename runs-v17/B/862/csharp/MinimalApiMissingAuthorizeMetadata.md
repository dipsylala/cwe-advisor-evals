## Verdict

Exploitable. The Minimal API endpoint for deleting documents performs a sensitive state-changing operation without any authorization check. Authentication middleware is configured and running, but authorization is not enforced on this specific route because the endpoint carries no `[Authorize]` attribute or `.RequireAuthorization()` call. An authenticated user (or an anonymous caller, depending on cookie authentication defaults) can delete any document by calling `DELETE /api/documents/{id}` with a valid ID.

## Source

**File:** Program.cs  
**Line:** 30  
**Code:** `app.MapDelete("/api/documents/{id}", DocumentEndpoints.DeleteDocument);`

The endpoint handler is in DocumentEndpoints.cs, which delegates to `DocumentService.DeleteAsync(id)`, a service method that removes the document from storage without any ownership or permission check.

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

The fix adds `.RequireAuthorization()` to the Minimal API endpoint registration. This attaches authorization metadata to the endpoint, requiring the caller to be authenticated and authorized before the handler executes. Unlike MVC controllers where `[Authorize]` on the class applies to all actions, Minimal API endpoints compute authorization per route and must declare their requirements explicitly through `.RequireAuthorization()`, endpoint metadata, or a centralized `FallbackPolicy`. Without this call, the endpoint is reachable by any caller, including unauthenticated users or authenticated users without the required role or permission.

## Behaviour changes

None. The `.RequireAuthorization()` method is a fluent builder extension on the endpoint returned by `MapDelete()`. It attaches authorization metadata and returns the same endpoint object for further chaining. It does not change the handler signature, return type, arguments, or service resolution—only enforcement. The handler and service layer remain unchanged. The endpoint will now challenge unauthenticated callers (triggering a redirect to the login flow under cookie authentication) and return 403 Forbidden to authenticated callers without the required authorization context.
