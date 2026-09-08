## Verdict

Confirmed. CWE-862 (Missing Authorization).

## Source

`app.MapDelete("/api/documents/{id}", DocumentEndpoints.DeleteDocument);` in `Program.cs` (line 30). This is a Minimal API route registered directly on `WebApplication`, separate from the MVC controller pipeline. ASP.NET Core computes authorization metadata per endpoint, so the `[Authorize]` attributes on `DocumentsController` have no effect on this route. No `FallbackPolicy` is configured (`AddAuthorization()` at line 12 uses the library default, which is "no restriction"), and the endpoint itself carries no `[Authorize]` and no `.RequireAuthorization()`. The result: `DELETE /api/documents/{id}` is reachable by any caller, including unauthenticated ones, and reaches `DocumentEndpoints.DeleteDocument`, which performs the delete.

## Fix

### File: Program.cs

```csharp
using DocumentPortal;
using DocumentPortal.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddAuthentication("Cookies").AddCookie("Cookies");

builder.Services.AddAuthorization();

builder.Services.AddScoped<IDocumentService, DocumentService>();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// MVC controllers (DocumentsController) are correctly protected with [Authorize]
// on every action. This route table is fine.
app.MapControllers();

// Minimal API endpoint added alongside the controller-based API. Authorization
// metadata is computed per endpoint, so it must be applied here explicitly -
// it does not inherit from DocumentsController's [Authorize] attributes.
app.MapDelete("/api/documents/{id}", DocumentEndpoints.DeleteDocument)
    .RequireAuthorization();

app.Run();
```

## Explanation

`.RequireAuthorization()` attaches an authorization requirement directly to this endpoint's metadata, which is exactly what ASP.NET Core's per-endpoint authorization model checks - the same mechanism `[Authorize]` populates for controller actions. With `UseAuthentication()` and `UseAuthorization()` already in the pipeline (lines 18-19) and `AddAuthorization()` registering the authorization services (line 12), calling `.RequireAuthorization()` with no arguments requires the caller to satisfy the default authorization policy (authenticated, using the cookie scheme configured at line 7). An anonymous request to `DELETE /api/documents/{id}` is now rejected with a 401/403 before `DocumentEndpoints.DeleteDocument` runs, closing the gap without touching the controller-based routes, which were already correctly protected.

An equally valid alternative for a codebase with many Minimal API endpoints is a `FallbackPolicy` in `AddAuthorization(options => options.FallbackPolicy = ...)`, which defaults every endpoint lacking its own metadata to require authorization; that is a broader, app-wide change rather than a fix scoped to this one route, so the per-endpoint `.RequireAuthorization()` is preferred here to keep the change minimal and match how the sibling controller endpoints already declare authorization explicitly.
