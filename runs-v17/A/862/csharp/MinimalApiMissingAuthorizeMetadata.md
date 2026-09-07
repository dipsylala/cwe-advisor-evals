## Verdict

**CONFIRMED**: CWE-862 (Missing Authorization). The Minimal API endpoint registered at line 30 lacks authorization metadata, allowing anonymous access to a sensitive operation.

## Source

The vulnerability exists in `Program.cs` at line 30:

```csharp
app.MapDelete("/api/documents/{id}", DocumentEndpoints.DeleteDocument);
```

The endpoint calls `DocumentEndpoints.DeleteDocument`, which invokes `documentService.DeleteAsync(id)` — a sensitive document deletion operation. No `.RequireAuthorization()` call protects this route, and no global `FallbackPolicy` was configured (line 12), so the endpoint is reachable by unauthenticated callers.

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

The fix adds `.RequireAuthorization()` to the endpoint registration chain. This method ensures that the endpoint requires an authenticated user, preventing anonymous access. In ASP.NET Core Minimal APIs, authorization metadata is computed per endpoint, so the `[Authorize]` attribute on `DocumentsController` does not apply. Each route must explicitly call `.RequireAuthorization()` or be covered by a global `FallbackPolicy` (which is not configured here).
