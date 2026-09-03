## Verdict

**Confirmed.** The DELETE endpoint at line 29 is a Minimal API route that carries no authorization metadata. It is reachable without authentication or authorization check, in contrast to the MVC controller actions on the same resource which carry `[Authorize]`. ASP.NET Core computes authorization metadata per endpoint, so `[Authorize]` on the controller does not apply to separately registered Minimal API routes.

## Source

**File:** `evals/cases/862/csharp/MinimalApiMissingAuthorizeMetadata/Program.cs`

**Line:** 29

**Vulnerable code:**
```csharp
app.MapDelete("/api/documents/{id}", DocumentEndpoints.DeleteDocument);
```

The endpoint carries no `[Authorize]` attribute, no `.RequireAuthorization()` call, and no resource-based ownership check. The `AddAuthorization()` call on line 11 contains no `FallbackPolicy` to inherit an authorization requirement, so this endpoint defaults to allowing anonymous access.

## Fix

Add `.RequireAuthorization()` to the endpoint registration to require authentication:

```csharp
app.MapDelete("/api/documents/{id}", DocumentEndpoints.DeleteDocument)
    .RequireAuthorization();
```

## Explanation

`.RequireAuthorization()` attaches an authorization policy requirement to the endpoint as metadata. When called without arguments, it enforces the `DefaultPolicy`, which requires the caller to be authenticated. This prevents anonymous access to the delete operation and brings the Minimal API endpoint into parity with the `[Authorize]` attribute on the sibling MVC controller actions.

If the operation requires resource-based authorization (e.g., verifying the caller owns the document being deleted) rather than role-based authorization, the handler method `DocumentEndpoints.DeleteDocument` should also call `IAuthorizationService.AuthorizeAsync(User, resource, policyName)` internally to check ownership before performing the deletion, as the centralized `.RequireAuthorization()` gate enforces only authentication, not resource ownership.

## Behaviour changes

- **Before:** Any caller (authenticated or anonymous) can issue a DELETE request to `/api/documents/{id}` and reach the handler.
- **After:** Only authenticated callers can reach the handler. Unauthenticated requests receive a 401 (Challenge) response. Authenticated callers with insufficient privileges (if a Policy or Roles constraint is added later) receive a 403 (Forbid) response.
- **No change to method signature, return value, or parameters:** The fix is purely metadata; the handler method signature and logic remain unchanged.
