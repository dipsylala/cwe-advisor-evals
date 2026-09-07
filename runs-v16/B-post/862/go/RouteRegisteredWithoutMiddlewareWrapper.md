## Verdict

CONFIRMED: The finding is valid. Line 103 registers `exportUsersHandler` without the required authorization middleware.

## Source

The vulnerability exists in the route registration at line 103 of `admin.go`:

```go
mux.HandleFunc("GET /admin/users/export", exportUsersHandler)
```

`exportUsersHandler` (lines 66-82) exports all users with their email addresses as CSV - a sensitive operation that requires administrative authorization. However, it is registered directly on the mux without the `requireAdmin` wrapper that protects the sibling routes `banUserHandler` (line 99) and `unbanUserHandler` (line 100).

The handler itself contains no authorization check; it relies entirely on the middleware applied at registration time. Because no middleware is applied here, any authenticated user can reach the endpoint and export the full user table, violating the separation between authentication (context has a valid user) and authorization (that user is permitted to perform this action).

## Fix

Line 103 must be changed from:

```go
mux.HandleFunc("GET /admin/users/export", exportUsersHandler)
```

to:

```go
mux.HandleFunc("GET /admin/users/export", requireAdmin(exportUsersHandler))
```

Wrap the handler with the existing `requireAdmin` middleware (defined at lines 31-44), matching the pattern already applied to `banUserHandler` and `unbanUserHandler`.

## Explanation

The fix applies the shared authorization middleware to the registration, enforcing the same role check used elsewhere in the package. The `requireAdmin` wrapper (1) reads the authenticated user from context, (2) verifies the user's role is "admin", and (3) only then passes control to the handler.

This eliminates the gap where any authenticated user, regardless of role, could reach a sensitive endpoint that exports the entire user table. The middleware is the centralized enforcement point recommended by both CWE-862 guidance and the Go language-specific guidance, which emphasizes that "wrap sensitive routes with a shared authorization middleware rather than duplicating checks inline, so the wrapper's absence is visible at the point of registration."

No changes to the handler itself are required; the vulnerability is purely at the registration site. The fix preserves the handler's existing contract: it continues to return CSV data on success and HTTP error responses on failure, with the addition of an authorization gate that denies unauthenticated and non-admin callers before the handler runs.

## Behaviour changes

- Authenticated non-admin users will now receive HTTP 403 (Forbidden) when attempting to access `GET /admin/users/export`, instead of receiving the full CSV export.
- Unauthenticated users will receive HTTP 401 (Unauthorized), matching the behaviour of the sibling ban/unban routes.
- Admin users will continue to receive the full user export as before.
