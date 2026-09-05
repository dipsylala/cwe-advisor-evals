## Verdict

Exploitable

## Source

Route handler registration at line 24 in `adminRoutes.js`: the GET `/admin/users/export` route chains `requireAuth` middleware but is missing the `requireRole('admin')` check that all sibling admin routes (ban, unban, delete) apply.

## Fix

**Vulnerable code:**
```javascript
router.get('/admin/users/export', requireAuth, exportUsersHandler);
```

**Fixed code:**
```javascript
router.get('/admin/users/export', requireAuth, requireRole('admin'), exportUsersHandler);
```

## Explanation

The new `/admin/users/export` route returns sensitive user data and should require the admin role, just as every other admin operation in this router does (ban, unban, delete). The route chain currently verifies the caller is authenticated via `requireAuth` but skips the role check on the handler, allowing any logged-in user to reach the export. Adding `requireRole('admin')` between authentication and the handler enforces the same authorization pattern used throughout the file and is the centralized mechanism already in place. An authenticated but non-admin user will now receive a 403 instead of being granted access to the export.

## Behaviour changes

None. The fix adds an authorization gate that did not exist before; it does not alter the arguments, return value, or response shape that the handler already produces - it only makes the handler unreachable to unprivileged callers.

