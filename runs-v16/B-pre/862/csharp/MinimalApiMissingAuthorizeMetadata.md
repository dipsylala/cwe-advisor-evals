## Verdict

Exploitable. An unauthenticated caller can invoke the DELETE endpoint at line 29 and execute `DocumentEndpoints.DeleteDocument` without any authorization check. The endpoint carries no `[Authorize]` attribute or `.RequireAuthorization()` call, and no `FallbackPolicy` is configured, so it is reachable by anonymous users.

## Source

The HTTP DELETE request to `/api/documents/{id}` from an unauthenticated caller. The request path includes an identifier parameter (`id`), which the handler uses to locate and delete a document. There is no prior check to verify the caller is authenticated or has permission to delete that specific document.

## Fix

**Vulnerable code (line 29):**
```csharp
app.MapDelete("/api/documents/{id}", DocumentEndpoints.DeleteDocument);
```

**Fixed code:**
```csharp
app.MapDelete("/api/documents/{id}", DocumentEndpoints.DeleteDocument)
    .RequireAuthorization();
```

## Explanation

The Minimal API endpoint was registered without authorization metadata. Unlike MVC controller actions, which inherit `[Authorize]` from the controller class, Minimal API endpoints are evaluated independently for authorization - metadata on a sibling MVC controller does not protect a separately registered route. Adding `.RequireAuthorization()` attaches an authorization requirement to the endpoint's metadata, ensuring it will be enforced by the `app.UseAuthorization()` middleware already registered at line 18. This blocks unauthenticated requests at the authorization middleware before the handler runs. For a delete operation on a specific document, the code should also implement resource-based authorization to verify the authenticated caller owns or has permission to delete that particular record, but the immediate fix addresses the missing authentication requirement.

## Behaviour changes

Unauthenticated requests to the endpoint are now rejected with a 401 (Unauthorized) or redirected to the login path (depending on the authentication scheme). Authenticated requests continue to reach the handler unchanged. This is the intended security fix - the endpoint was unprotected and should require authentication.
