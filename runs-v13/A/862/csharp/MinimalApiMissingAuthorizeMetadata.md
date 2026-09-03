## Verdict

Confirmed CWE-862. The Minimal API endpoint for deleting documents is registered without authorization metadata, allowing unauthenticated callers to reach it.

## Source

**File:** `Program.cs`, line 29

```csharp
app.MapDelete("/api/documents/{id}", DocumentEndpoints.DeleteDocument);
```

The endpoint carries no `.RequireAuthorization()` call and no `[Authorize]` metadata. The configuration on line 11 adds authorization services but omits a `FallbackPolicy`, which means endpoints without explicit authorization metadata are left unprotected.

## Fix

Add `.RequireAuthorization()` to the endpoint mapping:

```csharp
app.MapDelete("/api/documents/{id}", DocumentEndpoints.DeleteDocument).RequireAuthorization();
```

## Explanation

ASP.NET Core Minimal APIs compute authorization per endpoint. Unlike MVC controller actions decorated with `[Authorize]`, Minimal API endpoints require explicit `.RequireAuthorization()` calls to enforce authentication and authorization checks.

Without `.RequireAuthorization()`, the endpoint is reachable by any caller, authenticated or not. The fix establishes that this endpoint requires the caller to be authenticated before the handler is invoked, protecting sensitive document deletion operations.

The default authorization policy (established by `AddAuthorization()` without a `FallbackPolicy`) uses the `AuthenticateScheme` to verify the request has valid authentication credentials.
