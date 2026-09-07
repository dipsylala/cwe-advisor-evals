## Verdict

Exploitable. The `exportUsersHandler` route is registered on the mux without the `requireAdmin` authorization middleware, allowing any HTTP client to reach it and export the full user table including email addresses. The neighboring routes `banUserHandler` and `unbanUserHandler` are correctly wrapped with `requireAdmin`, but this one is not - a common oversight when adding routes after the initial authorization pattern is established.

## Source

Any HTTP client reaching the endpoint. No attacker-controlled input is required beyond the ability to make an HTTP GET request to `/admin/users/export`.

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

The `requireAdmin` middleware wrapper, already defined in the codebase and applied to the `banUserHandler` and `unbanUserHandler` routes, verifies that the authenticated user has the `"admin"` role before allowing the handler to execute. Applying the same wrapper to `exportUsersHandler` enforces that only admin-role users can export the user table, closing the authorization gap. The fix uses the existing centralized authorization mechanism already proven to work for sibling routes, rather than adding an inline check inside the handler body.

## Behaviour changes

None. The `requireAdmin` wrapper only adds an authorization check before calling `next(w, r)`. The handler's logic, arguments, and return values are unchanged. If the user lacks admin role, `requireAdmin` returns HTTP 403 Forbidden before `exportUsersHandler` is invoked.
