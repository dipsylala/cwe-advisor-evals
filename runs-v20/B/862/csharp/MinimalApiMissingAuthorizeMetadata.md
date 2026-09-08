## Verdict

Exploitable. Confidence: high.

CWE-862 (Missing Authorization) confirmed at `Program.cs:30` (the `app.MapDelete` registration flagged by the comment at line 29). The Minimal API endpoint carries no authorization metadata of its own, and `AddAuthorization()` (line 12) is called with no `FallbackPolicy`, so ASP.NET Core's default fallback (allow) applies to any endpoint that is not otherwise covered.

## Source

- Sink: `app.MapDelete("/api/documents/{id}", DocumentEndpoints.DeleteDocument)` in `Program.cs` - a Minimal API route with no `[Authorize]`, no `.RequireAuthorization()`, and no covering `FallbackPolicy`.
- Handler: `DocumentEndpoints.DeleteDocument(int id, IDocumentService documentService)` in `DocumentEndpoints.cs`, which calls `documentService.DeleteAsync(id)` and returns `204 No Content` on success or `404` if the id does not exist.
- Data flow: the route's `{id}` path segment is bound directly to the handler's `id` parameter and passed straight to `DeleteAsync`, with no authentication or authorization check anywhere on this path. Because Minimal API authorization metadata is computed per endpoint, the `[Authorize]` attribute on the sibling `DocumentsController` (which protects `GET`/`POST` on the same resource) does not extend to this separately registered route. Any caller, authenticated or not, can send `DELETE /api/documents/{id}` for any `id` and delete the corresponding document.
- Resource-level note: `DocumentService` has no per-document ownership concept exercised on delete (`DeleteAsync` removes by `id` alone, and `DocumentsController`'s own actions perform no ownership check either), so the gap here is authentication-level, matching the level of protection already applied to the sibling controller.

## Fix

### File: Program.cs

```csharp
using DocumentPortal;
using DocumentPortal.Services;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddAuthentication("Cookies").AddCookie("Cookies");

// A FallbackPolicy is required so that any endpoint carrying no authorization
// metadata of its own (no [Authorize], no .RequireAuthorization()) still needs
// an authenticated caller by default, instead of being reachable anonymously.
// This does not change endpoints that already carry [Authorize] - those are
// still evaluated against DefaultPolicy - so DocumentsController is unaffected.
builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

builder.Services.AddScoped<IDocumentService, DocumentService>();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// MVC controllers (DocumentsController) are correctly protected with [Authorize]
// on every action. This route table is fine.
app.MapControllers();

// Minimal API endpoint registered alongside the controller-based API. It carries
// no authorization metadata of its own, so it now falls under the FallbackPolicy
// configured above, which requires an authenticated caller.
app.MapDelete("/api/documents/{id}", DocumentEndpoints.DeleteDocument);

app.Run();
```

## Explanation

`AddAuthorization()` was called with no `FallbackPolicy`, so ASP.NET Core's default fallback behavior (allow anonymous access) applied to any endpoint - like the Minimal API `MapDelete` route - that carries no authorization metadata of its own. The fix sets `options.FallbackPolicy` to a policy requiring an authenticated user (`new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build()`), which is evaluated for every endpoint that has no explicit `[Authorize]`/`.RequireAuthorization()`/`[AllowAnonymous]` metadata. This closes the gap for the delete endpoint by requiring authentication before `DocumentEndpoints.DeleteDocument` executes, using the centralized mechanism (`AddAuthorization` in `Program.cs`) rather than an inline one-off check, so any future endpoint added without explicit metadata inherits the same requirement. It does not change `DocumentsController`, whose actions carry a bare `[Authorize]` and are evaluated against `DefaultPolicy`, not `FallbackPolicy`.

## Behaviour changes

- Requires an authenticated caller for `DELETE /api/documents/{id}`, where any caller (authenticated or not) could previously reach it. This is the finding's fix, not a new restriction beyond it.
- No role, policy, or resource-ownership check was added, and none was invented. This matches the level of protection already applied to the sibling `DocumentsController` actions, which use a bare `[Authorize]` (authenticated-user-only) with no role/policy/ownership check, and `DocumentService.DeleteAsync` has no ownership concept to check against.
- `DocumentsController`'s existing `[Authorize]`-protected actions are unaffected: they are evaluated against `DefaultPolicy`, which `FallbackPolicy` does not alter.
- Response codes on the endpoint are unchanged for the authenticated case: still `204 No Content` on successful delete, `404` when the id does not exist. An unauthenticated caller now gets a denial (redirect to the configured access-denied path under cookie authentication, since no explicit status-code behavior is configured for this Minimal API endpoint) instead of reaching the handler.
- Assumption: since the sibling controller and `DocumentService` implement no ownership model, this fix adds authentication only, not an ownership check - adding one would be inventing a permission the application does not otherwise express, which the guidance says to state separately rather than fold into this fix.

Verification: copied the case's `DocumentEndpoints.cs`, `DocumentService.cs`, and `DocumentsController.cs` unchanged alongside the fixed `Program.cs` into a scratch ASP.NET Core project (`dotnet new web`, .NET 10 SDK) and ran `dotnet build`. Build succeeded, 0 warnings, 0 errors, confirming `AuthorizationPolicyBuilder`, `RequireAuthenticatedUser()`, `Build()`, and the `FallbackPolicy` property all resolve correctly with the added `using Microsoft.AspNetCore.Authorization;`.
