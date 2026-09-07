## Verdict

**Exploitable** (High confidence)

The endpoint at line 29 accepts DELETE requests from any caller, including unauthenticated users, without any authorization check. This allows unauthorized deletion of documents.

## Source

Unauthenticated HTTP request to `DELETE /api/documents/{id}`.

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

The endpoint carries no authorization metadata, making it accessible to anonymous callers. Adding `.RequireAuthorization()` enforces the application's configured authorization policy on this endpoint, requiring the caller to be authenticated. Unauthenticated requests will receive a 401 Unauthorized response (or configured authentication challenge) instead of proceeding to the handler. This closes the missing authorization check at the endpoint registration level. Note that a complete fix also requires resource-based ownership verification within the handler to ensure authenticated callers can only delete documents they own.

## Behaviour changes

- **Authentication requirement added**: Anonymous requests to `DELETE /api/documents/{id}` now receive a 401 Unauthorized (or redirect) instead of reaching the handler
- **Policy enforcement**: Requests are evaluated against the application's default authorization policy configured in `Program.cs`
- **Authenticated without required role**: If the application has role or policy requirements, authenticated users without those roles receive a 403 Forbidden
- **No breaking changes to valid requests**: Properly authenticated and authorized requests proceed as before

## Additional notes

**Assumptions:** The application has a default authorization policy configured via `AddAuthorization()` in Program.cs. The `.RequireAuthorization()` method is part of ASP.NET Core's standard authorization middleware and is valid for Minimal API endpoints in ASP.NET Core 3.0+.

**Incomplete fix:** While this change closes the missing authentication check at the endpoint level, it does not implement resource-based authorization (ownership checks). For a complete remediation, the handler should also verify that the authenticated caller owns the document being deleted by calling `IAuthorizationService.AuthorizeAsync(User, resource, "CanDeleteDocument")` or similar inside the handler.
