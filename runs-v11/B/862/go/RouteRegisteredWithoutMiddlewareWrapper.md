## Verdict

Exploitable. The `exportUsersHandler` route is registered without authorization middleware, allowing any authenticated user to export the full user table including email addresses. Comparable routes (`banUserHandler`, `unbanUserHandler`) are correctly protected with `requireAdmin`, but this route was added later and omitted the wrapper.

## Source

The vulnerability originates at the route registration site in `RegisterRoutes` (line 103), where the handler is connected to its pattern without the `requireAdmin` middleware that gates access to comparable sensitive operations.

The `exportUsersHandler` itself (lines 66-82) correctly exports user data, but has no authorization gate of its own—it relies entirely on the protection expected at registration. When registered without `requireAdmin`, it executes for any caller, including those without admin role.

## Fix

Wrap the `exportUsersHandler` with `requireAdmin` at the registration point, matching the pattern used for other sensitive routes:

**Vulnerable code:**
```go
mux.HandleFunc("GET /admin/users/export", exportUsersHandler)
```

**Fixed code:**
```go
mux.HandleFunc("GET /admin/users/export", requireAdmin(exportUsersHandler))
```

## Explanation

The `requireAdmin` middleware (lines 31-44) checks that an authenticated user holds the "admin" role before forwarding the request to the wrapped handler. Without this middleware, `exportUsersHandler` executes for every authenticated caller, regardless of role. Applying the wrapper at registration ensures the authorization gate runs before the handler can export sensitive data, aligning this route with the existing protection pattern used by `banUserHandler` and `unbanUserHandler`.

## Behaviour changes

The route now enforces role-based authorization before allowing the export operation. When an authenticated user without the admin role calls `GET /admin/users/export`, the response changes from a CSV export (200) to an HTTP 403 Forbidden error. Users with the admin role see no change in behavior. This closes the authorization gap without altering the handler's contract—it still returns the same CSV data, but now only to authorized callers.
