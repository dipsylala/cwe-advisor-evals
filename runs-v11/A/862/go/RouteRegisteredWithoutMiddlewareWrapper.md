## Verdict
Confirmed. The route handler `exportUsersHandler` accesses sensitive data without authorization checks, violating CWE-862.

## Source
Line 103 in `RegisterRoutes()`:
```go
mux.HandleFunc("GET /admin/users/export", exportUsersHandler)
```

The handler itself at lines 66-82 loads and streams all user records including email addresses and roles, with no permission validation. Other sensitive routes at lines 99-100 use the `requireAdmin` middleware, but this one does not.

## Fix
Wrap the handler with the existing `requireAdmin` middleware, consistent with the pattern used for other sensitive admin operations:

```go
mux.HandleFunc("GET /admin/users/export", requireAdmin(exportUsersHandler))
```

## Explanation
The `requireAdmin` wrapper (lines 31-44) checks that the request carries an authenticated session user with the `"admin"` role before allowing the handler to execute. Without this wrapper, any unauthenticated or non-admin user can reach `exportUsersHandler`, which exports the entire user table including private email addresses and role assignments.

The vulnerability exists because the route was added later (line 95-97 comment) without applying the same authorization guard used elsewhere. The fix is a one-word addition that applies the existing, tested authorization mechanism.
