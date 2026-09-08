## Verdict

Missing Authorization on Minimal API endpoint. The DELETE endpoint at line 30 performs a sensitive operation (document deletion) without any authorization metadata, making it reachable by unauthenticated and unprivileged users. Authorization is computed per endpoint in ASP.NET Core Minimal APIs; the `[Authorize]` attribute on the MVC controller does not protect this separately registered route.

## Source

Minimal API endpoint registration without authorization metadata:
```csharp
app.MapDelete("/api/documents/{id}", DocumentEndpoints.DeleteDocument);
```

The endpoint handler at line 30 is reachable by any caller, including unauthenticated users. Comparable controller-based routes are protected with `[Authorize]`, but this Minimal API requires its own explicit authorization check.

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

The fix adds `.RequireAuthorization()` to the Minimal API endpoint registration, attaching authorization metadata that requires the caller to be authenticated. This matches the pattern applied to the MVC controller actions via the `[Authorize]` attribute. The `RequireAuthorization()` method chains on the `RouteHandlerBuilder` returned by `MapDelete()`, adding the check to the endpoint's metadata without requiring a separate middleware or policy configuration. The call uses the same centralized authentication and authorization pipeline already wired in the application (`AddAuthentication`, `AddAuthorization`, `UseAuthentication`, `UseAuthorization`), and requires any authenticated user — the same gate as a bare `[Authorize]` attribute on the controller. No new dependencies or configuration changes are needed; this is an endpoint-level metadata addition to align with the existing authorization posture.

## Behaviour changes

The endpoint `/api/documents/{id}` via DELETE previously accepted requests from all callers (authenticated and unauthenticated). After the fix, it rejects unauthenticated requests with a 401 Unauthorized response (a redirect to the login path under cookie authentication) and requires a valid authentication ticket. Callers who are already authenticated but lack the required authorization (if further policy-based or resource-level checks are later added to the handler) will receive a 403 Forbidden response. Legitimate authenticated users performing authorized deletes see no change in behavior.
