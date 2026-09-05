## Verdict

Missing authorization on the `/admin/users/export` route. The handler exports the entire user table including email addresses but is registered without the `requireAdmin` middleware that protects other sensitive admin operations in the same package.

## Source

Line 103 in `admin.go`:
```
mux.HandleFunc("GET /admin/users/export", exportUsersHandler)
```

The `exportUsersHandler` exports all user records including email addresses (line 66–82) and requires the same authorization level as `banUserHandler` and `unbanUserHandler` (per the comments on lines 46–47 and 64–65), yet it is the only admin handler registered without the `requireAdmin` wrapper.

## Fix

Wrap `exportUsersHandler` with `requireAdmin` at line 103:
```
mux.HandleFunc("GET /admin/users/export", requireAdmin(exportUsersHandler))
```

This aligns with the registration pattern for `banUserHandler` and `unbanUserHandler` (lines 99–100), which are both protected by the same middleware.

## Explanation

The `requireAdmin` middleware (lines 31–44) validates that the request carries an authenticated session with the `"admin"` role before the handler runs. Without this check, any caller—authenticated or not—can invoke `/admin/users/export` and retrieve the full user table.

The vulnerability is not in the handler logic itself (which correctly reads and formats user data) but in the absence of authorization enforcement at the route registration boundary. The fix applies the existing authorization middleware at registration time, preventing unauthorized access to the sensitive data export endpoint.
