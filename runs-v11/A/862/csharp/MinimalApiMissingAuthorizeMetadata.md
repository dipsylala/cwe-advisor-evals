## Verdict

**Confirmed.** The minimal API endpoint `DeleteDocument` at line 29 lacks authorization metadata. While the equivalent MVC controller action carries `[Authorize]`, this minimal API endpoint is registered with no authorization requirement and is therefore reachable by anonymous callers.

## Source

```csharp
app.MapDelete("/api/documents/{id}", DocumentEndpoints.DeleteDocument);
```

The endpoint mapping carries no `.RequireAuthorization()` call and the handler method has no authorization attributes. The absence of both means ASP.NET Core treats this as a public endpoint.

## Fix

```csharp
app.MapDelete("/api/documents/{id}", DocumentEndpoints.DeleteDocument).RequireAuthorization();
```

Attach `.RequireAuthorization()` to the endpoint mapping. This enforces that the endpoint requires an authenticated user, matching the authorization semantics of the `[Authorize]`-decorated controller action.

## Explanation

Minimal API endpoints and MVC controllers have independent authorization metadata. The `[Authorize]` attribute on `DocumentsController.DeleteDocument` does not extend to this separately registered route. 

In ASP.NET Core, when no authorization policy is configured as a `FallbackPolicy` at the application level (line 11 uses `AddAuthorization()` without setting one), endpoints must declare their own authorization requirements to be protected. The comments in the original code acknowledge this: "any endpoint that carries no authorization metadata of its own... is reachable by anonymous callers."

Calling `.RequireAuthorization()` on the endpoint mapping registers the required authorization metadata, ensuring the endpoint enforces authentication before allowing access.
