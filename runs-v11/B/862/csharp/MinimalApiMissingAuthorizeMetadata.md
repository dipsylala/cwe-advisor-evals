## Verdict

exploitable

## Source

HTTP DELETE request to `/api/documents/{id}` from line 29 in Program.cs

## Fix

**Vulnerable code:**
```csharp
app.MapDelete("/api/documents/{id}", DocumentEndpoints.DeleteDocument);
```

**Fixed code:**
```csharp
app.MapDelete("/api/documents/{id}", DocumentEndpoints.DeleteDocument).RequireAuthorization();
```

## Explanation

The Minimal API endpoint registered at line 29 performs a sensitive DELETE operation on a document resource but carries no authorization metadata. While authentication middleware is configured in the application, authorization is computed per endpoint in ASP.NET Core Minimal APIs, and `[Authorize]` on the MVC controller does not apply to separately registered routes. The fix adds `.RequireAuthorization()` to the endpoint, which enforces that the caller must be authenticated before the handler executes. This addresses the missing authorization check at the endpoint level. For complete remediation, the handler `DocumentEndpoints.DeleteDocument` should also verify the authenticated user owns or has permission to delete the specific document via resource-based authorization using `IAuthorizationService.AuthorizeAsync()`.

## Behaviour changes

`.RequireAuthorization()` enforces authentication by default (requires an authenticated `ClaimsPrincipal`). Unauthenticated requests will receive a 401 Unauthorized response before the handler is invoked, whereas the original code allowed any caller (authenticated or anonymous) to reach the handler. No arguments are altered, and return values remain unchanged; the authorization metadata is attached as endpoint metadata and evaluated by the ASP.NET Core authorization middleware before handler execution.
