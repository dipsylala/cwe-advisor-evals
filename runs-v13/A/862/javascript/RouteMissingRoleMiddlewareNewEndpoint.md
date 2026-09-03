## Verdict

The route handler at line 24 is missing authorization middleware. It checks authentication (`requireAuth`) but not the admin role required for the sensitive data-export operation. The fix is to add the `requireRole('admin')` middleware to match the authorization pattern established by sibling admin routes.

## Source

```javascript
router.get('/admin/users/export', requireAuth, exportUsersHandler);
```

Line 24 registers a GET endpoint for `/admin/users/export`. The middleware chain contains only `requireAuth`, which verifies the user is logged in. However, the operation—exporting all user data—is sensitive and requires the admin role check that all sibling routes on lines 15–17 apply.

## Fix

```javascript
router.get('/admin/users/export', requireAuth, requireRole('admin'), exportUsersHandler);
```

Add `requireRole('admin')` after `requireAuth` in the middleware chain. This enforces that only users holding the admin role can access the bulk export endpoint, consistent with the authorization model for other admin operations (ban, unban, delete) defined in the same file.

## Explanation

CWE-862 (Missing Authorization) arises when code authenticates a user but fails to verify they have the necessary permissions for a sensitive operation. Here, the route accepts any authenticated user, bypassing the role check that protects other admin endpoints. The fix introduces the missing authorization check using the existing `requireRole` middleware, which evaluates the caller's role before the handler executes. This ensures the endpoint enforces role-based access control consistently with the rest of the admin API surface.
