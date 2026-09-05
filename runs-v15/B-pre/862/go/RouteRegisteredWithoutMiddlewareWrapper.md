## Verdict

Exploitable. An unauthenticated or non-admin user can call GET /admin/users/export and receive the full user table including email addresses and roles, bypassing the authorization requirement enforced on equivalent sensitive endpoints (ban and unban).

## Source

HTTP request to GET /admin/users/export, registered at line 103 of admin.go without the `requireAdmin` middleware wrapper.

## Fix

**Vulnerable code (line 103):**
```go
mux.HandleFunc("GET /admin/users/export", exportUsersHandler)
```

**Fixed code:**
```go
mux.HandleFunc("GET /admin/users/export", requireAdmin(exportUsersHandler))
```

## Explanation

The `exportUsersHandler` performs a sensitive operation—streaming the full user table as CSV—but the route registration omits the `requireAdmin` middleware wrapper that is correctly applied to the ban and unban endpoints. Wrapping the handler registration with `requireAdmin` ensures the request passes through the authorization check before the handler executes, denying access to any caller who is not authenticated or who lacks the admin role. This matches the protection pattern already in place for comparable sensitive actions and prevents the unauthorized data disclosure.

## Behaviour changes

None. The `requireAdmin` middleware preserves the original handler contract: it verifies the authenticated user has the admin role (by reading the context and checking the role field), then calls the wrapped handler with the same request and response writer. The handler's behavior—loading users and streaming CSV—remains unchanged when called from an admin, and the middleware's early denial (returning 401 or 403) produces the correct response for non-admin callers without invoking the handler body.
